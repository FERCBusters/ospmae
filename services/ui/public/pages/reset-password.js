(() => {
  const msgEl = document.getElementById('msg');
  const form = document.getElementById('resetForm');
  const btn = document.getElementById('resetBtn');

  function setMsg(text, kind = 'info') {
    if (!msgEl) return;
    msgEl.textContent = text || '';
    msgEl.className = 'small mb-2 ' + (kind === 'error' ? 'text-danger' : 'text-secondary');
  }

  function getToken() {
    return new URLSearchParams(window.location.search).get('token') || '';
  }

  async function ensureEnabled() {
    try {
      const methods = await window.OSPMAE?.api?.('/v1/auth/methods', { allowErrorStatuses: [404, 500] });
      if (!methods || !methods.password_reset_enabled) {
        window.location.replace('/login.html');
      }
    } catch {
      window.location.replace('/login.html');
    }
  }

  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    btn.disabled = true;

    const token = getToken();
    const new_password = String(document.getElementById('newPassword')?.value || '');
    const confirm_password = String(document.getElementById('confirmPassword')?.value || '');

    if (!token) {
      setMsg('Missing reset token. Please request a new reset link.', 'error');
      btn.disabled = false;
      return;
    }
    if (!new_password || new_password.length < 8) {
      setMsg('Password must be at least 8 characters.', 'error');
      btn.disabled = false;
      return;
    }
    if (new_password !== confirm_password) {
      setMsg('Passwords do not match.', 'error');
      btn.disabled = false;
      return;
    }

    try {
      setMsg('Resetting password…');
      await window.OSPMAE?.api?.('/v1/auth/reset-password', {
        method: 'POST',
        body: { token, new_password, confirm_password },
      });
      setMsg('Password updated. Redirecting…');
      window.setTimeout(() => window.location.replace('/login.html'), 800);
    } catch (err) {
      console.error(err);
      setMsg(err?.message || 'Reset failed. The link may have expired.', 'error');
    } finally {
      btn.disabled = false;
    }
  });

  ensureEnabled();
})();
