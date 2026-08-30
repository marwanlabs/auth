// Thin wrapper around fetch() for the auth API. Cookies (session + CSRF)
// are sent automatically by the browser; we just need to echo the CSRF
// cookie back as a header on state-changing requests.

function getCookie(name) {
  const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? decodeURIComponent(match[2]) : null;
}

async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  const method = (options.method || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') {
    const csrf = getCookie('csrf_token');
    if (csrf) headers['X-CSRF-Token'] = csrf;
  }
  const res = await fetch(path, { ...options, headers, credentials: 'same-origin' });
  let body = null;
  try { body = await res.json(); } catch (_) { /* empty body */ }
  if (!res.ok) {
    const message = (body && body.error) || `Request failed (${res.status})`;
    throw new Error(message);
  }
  return body;
}

const Auth = {
  signup: (email, password) => api('/api/signup', { method: 'POST', body: JSON.stringify({ email, password }) }),
  login: (email, password) => api('/api/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  logout: () => api('/api/logout', { method: 'POST' }),
  me: () => api('/api/me'),
  changePassword: (current_password, new_password) =>
    api('/api/change-password', { method: 'POST', body: JSON.stringify({ current_password, new_password }) }),
  listSessions: () => api('/api/sessions'),
  revokeSession: (session_id) => api('/api/sessions/revoke', { method: 'POST', body: JSON.stringify({ session_id }) }),
  requestReset: (email) => api('/api/password-reset/request', { method: 'POST', body: JSON.stringify({ email }) }),
  confirmReset: (token, new_password) =>
    api('/api/password-reset/confirm', { method: 'POST', body: JSON.stringify({ token, new_password }) }),
  listUsers: () => api('/api/admin/users'),
  changeUserRole: (user_id, role) =>
    api('/api/admin/users/role', { method: 'POST', body: JSON.stringify({ user_id, role }) }),
  changeUserStatus: (user_id, disabled) =>
    api('/api/admin/users/status', { method: 'POST', body: JSON.stringify({ user_id, disabled }) }),
  deleteUser: (user_id) =>
    api('/api/admin/users/delete', { method: 'POST', body: JSON.stringify({ user_id }) }),
  listProviders: () => api('/api/auth/providers'),
  listAdminProviders: () => api('/api/admin/providers'),
  setProvider: (provider, enabled) =>
    api('/api/admin/providers', { method: 'POST', body: JSON.stringify({ provider, enabled }) }),
};

// Redirects an unauthenticated visitor to the login page. Call at the top
// of any page that requires a session.
async function requireAuth() {
  try {
    return await Auth.me();
  } catch (_) {
    window.location.href = '/login.html';
    return null;
  }
}

function showError(el, err) {
  el.textContent = err.message || String(err);
  el.hidden = false;
}

// Shared light/dark theme toggle for every page.
(function setupTheme() {
  const saved = localStorage.getItem('authserver-theme');
  const theme = saved || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  document.documentElement.dataset.theme = theme;

  function addToggle() {
    if (!document.body || document.querySelector('.theme-toggle')) return;
    const button = document.createElement('button');
    button.className = 'theme-toggle';
    button.type = 'button';
    button.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
    button.addEventListener('click', () => {
      const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
      document.documentElement.dataset.theme = next;
      localStorage.setItem('authserver-theme', next);
      button.textContent = next === 'dark' ? '☀' : '☾';
      button.setAttribute('aria-label', next === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
    });
    button.textContent = theme === 'dark' ? '☀' : '☾';
    document.body.appendChild(button);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', addToggle);
  else addToggle();
})();
