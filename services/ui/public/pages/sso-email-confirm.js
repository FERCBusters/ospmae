// Confirms a mailed SSO email address proof, as KEEN's sso-email page does.
(() => {
  const token = new URLSearchParams(window.location.hash.slice(1)).get("token");
  // The one-time token leaves the address bar before anything else runs.
  window.history.replaceState(null, "", window.location.pathname);
  const button = document.getElementById("confirmEmail");
  const status = document.getElementById("emailProofStatus");
  if (!token) {
    button.hidden = true;
    status.textContent =
      "Open the verification link from your email while signed into the account that requested it.";
  }
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      const result = await window.OSPMAE.api("/v1/me/sso-emails/confirm", {
        method: "POST",
        body: { token },
      });
      status.textContent =
        result.email + " is verified and available for SSO linking.";
      button.hidden = true;
    } catch (error) {
      status.textContent =
        (error?.message || String(error)) +
        " Sign into the requesting account and reopen the email link, or request a fresh link from Account → Password & security.";
      button.disabled = false;
    }
  });
})();
