(function () {
  var csrfHeaders = { "X-CSRF-Protection": "1" };

  function navigateToHttpUrl(value, fallback) {
    if (typeof value !== "string") {
      window.location.href = fallback;
      return;
    }

    try {
      var target = new URL(value, window.location.origin);
      if (target.protocol === "https:" || target.origin === window.location.origin) {
        window.location.href = target.toString();
        return;
      }
    } catch {
      window.location.href = fallback;
      return;
    }

    window.location.href = fallback;
  }

  async function loadSession() {
    try {
      var res = await fetch("/demo/session");
      var data = await res.json();

      if (!data.authenticated) {
        window.location.href = "/";
        return;
      }

      document.getElementById("loading").style.display = "none";
      document.getElementById("dashboard").style.display = "block";

      document.getElementById("user-id").textContent = data.userId || "-";
      document.getElementById("email").textContent = data.email || "-";
      document.getElementById("display-name").textContent = data.displayName || "-";
      document.getElementById("mfa-method").textContent = data.mfaMethod || "N/A";
      document.getElementById("auth-time").textContent =
        data.authenticatedAt ? new Date(data.authenticatedAt).toLocaleString() : "-";

      var methods = Array.isArray(data.enrolledMethods) ? data.enrolledMethods : [];
      document.getElementById("enrolled-methods").textContent =
        methods.length ? methods.join(", ").replace(/_/g, " ") : "-";

      var badge = document.getElementById("mfa-badge");
      if (data.provider === "davinci") {
        document.getElementById("user-id-label").textContent = "Signed in as";
        document.querySelectorAll("[data-legacy]").forEach(function (el) { el.style.display = "none"; });
        document.querySelectorAll("[data-davinci]").forEach(function (el) { el.style.display = ""; });
        badge.textContent = "Verified by Authsignal";
        badge.className = "badge badge-success";
      } else if (data.mfaVerified) {
        badge.textContent = "MFA Verified";
        badge.className = "badge badge-success";
      } else {
        badge.textContent = "No MFA";
        badge.className = "badge badge-warning";
      }
    } catch {
      window.location.href = "/";
    }
  }

  async function openMfaSettings() {
    try {
      var res = await fetch("/demo/mfa-settings", {
        method: "POST",
        headers: csrfHeaders,
      });
      var data = await res.json();

      if (data.settingsUrl) {
        navigateToHttpUrl(data.settingsUrl, "/dashboard.html");
      } else {
        alert("Could not load MFA settings. Please ensure you have Authsignal configured with the settings action.");
      }
    } catch (err) {
      var message = err instanceof Error ? err.message : "unknown error";
      alert("Failed to open MFA settings: " + message);
    }
  }

  async function logout() {
    var res = await fetch("/demo/logout", {
      method: "POST",
      headers: csrfHeaders,
    });
    var data = await res.json();

    if (data.signoffUrl) {
      navigateToHttpUrl(data.signoffUrl, "/");
    } else {
      window.location.href = "/";
    }
  }

  document.getElementById("logout-btn").addEventListener("click", logout);
  document.getElementById("mfa-settings-btn").addEventListener("click", openMfaSettings);

  loadSession();
})();
