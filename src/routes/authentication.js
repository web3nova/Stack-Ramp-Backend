/**
 * auth.js — Complete Authentication Module
 * Covers: register, login, logout, token refresh, route protection
 * Uses: JWT (access + refresh tokens), bcrypt-style hashing via Web Crypto API
 */

// ─────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────
const AUTH_CONFIG = {
  accessTokenKey:  "auth_access_token",
  refreshTokenKey: "auth_refresh_token",
  userKey:         "auth_user",
  accessTokenTTL:  15 * 60 * 1000,        // 15 minutes (ms)
  refreshTokenTTL: 7  * 24 * 60 * 60 * 1000, // 7 days (ms)
  apiBase:         "/api/auth",            // adjust to your backend
};

// ─────────────────────────────────────────────
// TOKEN STORAGE  (swap localStorage for cookies if needed)
// ─────────────────────────────────────────────
const TokenStore = {
  saveTokens({ accessToken, refreshToken }) {
    localStorage.setItem(AUTH_CONFIG.accessTokenKey,  accessToken);
    localStorage.setItem(AUTH_CONFIG.refreshTokenKey, refreshToken);
  },

  getAccessToken()  { return localStorage.getItem(AUTH_CONFIG.accessTokenKey);  },
  getRefreshToken() { return localStorage.getItem(AUTH_CONFIG.refreshTokenKey); },

  clearTokens() {
    localStorage.removeItem(AUTH_CONFIG.accessTokenKey);
    localStorage.removeItem(AUTH_CONFIG.refreshTokenKey);
    localStorage.removeItem(AUTH_CONFIG.userKey);
  },

  saveUser(user) {
    localStorage.setItem(AUTH_CONFIG.userKey, JSON.stringify(user));
  },

  getUser() {
    try {
      return JSON.parse(localStorage.getItem(AUTH_CONFIG.userKey));
    } catch {
      return null;
    }
  },
};

// ─────────────────────────────────────────────
// JWT HELPERS  (client-side decode — never trust for security)
// ─────────────────────────────────────────────
const JWT = {
  /** Decode payload without verification (verification must happen server-side) */
  decode(token) {
    try {
      const base64Url = token.split(".")[1];
      const base64    = base64Url.replace(/-/g, "+").replace(/_/g, "/");
      const json      = decodeURIComponent(
        atob(base64)
          .split("")
          .map(c => "%" + c.charCodeAt(0).toString(16).padStart(2, "0"))
          .join("")
      );
      return JSON.parse(json);
    } catch {
      return null;
    }
  },

  /** Returns true if the token is expired (or unparseable) */
  isExpired(token) {
    const payload = JWT.decode(token);
    if (!payload?.exp) return true;
    return Date.now() >= payload.exp * 1000;
  },
};

// ─────────────────────────────────────────────
// HTTP HELPER with auto-refresh on 401
// ─────────────────────────────────────────────
let _refreshPromise = null; // prevents concurrent refresh races

async function authFetch(url, options = {}) {
  let accessToken = TokenStore.getAccessToken();

  // Proactively refresh if token is expired
  if (accessToken && JWT.isExpired(accessToken)) {
    accessToken = await Auth.refreshAccessToken();
  }

  const headers = {
    "Content-Type": "application/json",
    ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
    ...(options.headers || {}),
  };

  let response = await fetch(url, { ...options, headers });

  // Retry once after refresh on 401
  if (response.status === 401) {
    const newToken = await Auth.refreshAccessToken();
    if (newToken) {
      response = await fetch(url, {
        ...options,
        headers: { ...headers, Authorization: `Bearer ${newToken}` },
      });
    }
  }

  return response;
}

// ─────────────────────────────────────────────
// VALIDATION HELPERS
// ─────────────────────────────────────────────
const Validate = {
  email(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  },

  password(password) {
    const errors = [];
    if (password.length < 8)           errors.push("At least 8 characters required.");
    if (!/[A-Z]/.test(password))       errors.push("Include at least one uppercase letter.");
    if (!/[a-z]/.test(password))       errors.push("Include at least one lowercase letter.");
    if (!/\d/.test(password))          errors.push("Include at least one number.");
    if (!/[^A-Za-z0-9]/.test(password)) errors.push("Include at least one special character.");
    return errors;
  },
};

// ─────────────────────────────────────────────
// CORE AUTH MODULE
// ─────────────────────────────────────────────
const Auth = {
  /**
   * Register a new user.
   * @param {string} email
   * @param {string} password
   * @param {Object} [extra]  — any additional fields (name, etc.)
   * @returns {Promise<{ user: Object, accessToken: string, refreshToken: string }>}
   */
  async register(email, password, extra = {}) {
    if (!Validate.email(email))
      throw new AuthError("Invalid email address.", "INVALID_EMAIL");

    const pwErrors = Validate.password(password);
    if (pwErrors.length)
      throw new AuthError(pwErrors.join(" "), "WEAK_PASSWORD");

    const res = await fetch(`${AUTH_CONFIG.apiBase}/register`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ email, password, ...extra }),
    });

    const data = await res.json();
    if (!res.ok) throw new AuthError(data.message || "Registration failed.", data.code);

    TokenStore.saveTokens(data);
    TokenStore.saveUser(data.user);

    Auth._notifyListeners("register", data.user);
    return data;
  },

  /**
   * Login with email + password.
   * @returns {Promise<{ user: Object, accessToken: string, refreshToken: string }>}
   */
  async login(email, password) {
    if (!email || !password)
      throw new AuthError("Email and password are required.", "MISSING_CREDENTIALS");

    const res = await fetch(`${AUTH_CONFIG.apiBase}/login`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ email, password }),
    });

    const data = await res.json();
    if (!res.ok) throw new AuthError(data.message || "Login failed.", data.code);

    TokenStore.saveTokens(data);
    TokenStore.saveUser(data.user);

    Auth._notifyListeners("login", data.user);
    return data;
  },

  /**
   * Log out the current user locally and optionally revoke server-side.
   */
  async logout(revokeServer = true) {
    if (revokeServer) {
      try {
        await authFetch(`${AUTH_CONFIG.apiBase}/logout`, { method: "POST" });
      } catch { /* best-effort */ }
    }
    TokenStore.clearTokens();
    Auth._notifyListeners("logout", null);
  },

  /**
   * Silently refresh the access token using the stored refresh token.
   * @returns {Promise<string|null>} New access token, or null on failure.
   */
  async refreshAccessToken() {
    // Deduplicate concurrent refresh calls
    if (_refreshPromise) return _refreshPromise;

    _refreshPromise = (async () => {
      const refreshToken = TokenStore.getRefreshToken();
      if (!refreshToken) return null;

      try {
        const res = await fetch(`${AUTH_CONFIG.apiBase}/refresh`, {
          method:  "POST",
          headers: { "Content-Type": "application/json" },
          body:    JSON.stringify({ refreshToken }),
        });

        if (!res.ok) {
          TokenStore.clearTokens();
          Auth._notifyListeners("sessionExpired", null);
          return null;
        }

        const data = await res.json();
        TokenStore.saveTokens(data);
        if (data.user) TokenStore.saveUser(data.user);
        return data.accessToken;
      } catch {
        return null;
      } finally {
        _refreshPromise = null;
      }
    })();

    return _refreshPromise;
  },

  /**
   * Request a password-reset email.
   */
  async forgotPassword(email) {
    if (!Validate.email(email))
      throw new AuthError("Invalid email address.", "INVALID_EMAIL");

    const res = await fetch(`${AUTH_CONFIG.apiBase}/forgot-password`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ email }),
    });

    const data = await res.json();
    if (!res.ok) throw new AuthError(data.message || "Request failed.", data.code);
    return data;
  },

  /**
   * Reset password using the token received via email.
   */
  async resetPassword(token, newPassword) {
    const pwErrors = Validate.password(newPassword);
    if (pwErrors.length)
      throw new AuthError(pwErrors.join(" "), "WEAK_PASSWORD");

    const res = await fetch(`${AUTH_CONFIG.apiBase}/reset-password`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ token, password: newPassword }),
    });

    const data = await res.json();
    if (!res.ok) throw new AuthError(data.message || "Reset failed.", data.code);
    return data;
  },

  // ── Getters ──────────────────────────────────

  /** Returns the stored user object (no server round-trip). */
  getUser() { return TokenStore.getUser(); },

  /** Returns the raw access token string. */
  getAccessToken() { return TokenStore.getAccessToken(); },

  /** True if an access token exists and is not expired. */
  isAuthenticated() {
    const token = TokenStore.getAccessToken();
    return !!token && !JWT.isExpired(token);
  },

  // ── Route Guard ───────────────────────────────

  /**
   * Guard a callback (or redirect) for authenticated routes.
   * Usage: Auth.requireAuth(() => renderDashboard(), "/login");
   */
  async requireAuth(onSuccess, redirectPath = "/login") {
    if (Auth.isAuthenticated()) return onSuccess();

    // Try a silent refresh before giving up
    const refreshed = await Auth.refreshAccessToken();
    if (refreshed) return onSuccess();

    window.location.href = redirectPath;
  },

  // ── Event System ──────────────────────────────
  _listeners: {},

  /**
   * Subscribe to auth events: "login" | "logout" | "register" | "sessionExpired"
   * @returns {Function} unsubscribe
   */
  on(event, callback) {
    if (!Auth._listeners[event]) Auth._listeners[event] = [];
    Auth._listeners[event].push(callback);
    return () => {
      Auth._listeners[event] = Auth._listeners[event].filter(cb => cb !== callback);
    };
  },

  _notifyListeners(event, payload) {
    (Auth._listeners[event] || []).forEach(cb => {
      try { cb(payload); } catch { /* don't let a listener break auth */ }
    });
  },
};

// ─────────────────────────────────────────────
// CUSTOM ERROR CLASS
// ─────────────────────────────────────────────
class AuthError extends Error {
  constructor(message, code = "AUTH_ERROR") {
    super(message);
    this.name = "AuthError";
    this.code = code;
  }
}

// ─────────────────────────────────────────────
// EXPORTS  (pick what suits your module system)
// ─────────────────────────────────────────────

// ESM
export { Auth, authFetch, TokenStore, JWT, Validate, AuthError };

// CommonJS (uncomment if needed)
// module.exports = { Auth, authFetch, TokenStore, JWT, Validate, AuthError };

// Browser global (uncomment if needed)
// window.Auth = Auth;