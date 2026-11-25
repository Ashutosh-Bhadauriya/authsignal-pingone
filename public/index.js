(function () {
  var banner = document.getElementById("error-banner");
  var card = document.querySelector(".card");
  var stage = document.getElementById("dv-stage");
  var statusLine = document.getElementById("dv-status");
  var params = new URLSearchParams(window.location.search);

  function showError(message) {
    banner.textContent = message;
    banner.style.display = "block";
    card.style.display = "";
    stage.style.display = "none";
  }

  var error = params.get("error");
  if (error) {
    showError(error);
    history.replaceState(null, "", "/");
  }

  // ─── DaVinci widget ───────────────────────────────────────────────────────

  function loadScript(src) {
    return new Promise(function (resolve, reject) {
      var el = document.createElement("script");
      el.src = src;
      el.onload = resolve;
      el.onerror = function () { reject(new Error("Could not load " + src)); };
      document.head.appendChild(el);
    });
  }

  function loadStyle(href) {
    var el = document.createElement("link");
    el.rel = "stylesheet";
    el.href = href;
    document.head.appendChild(el);
  }

  var assetsLoaded = null;
  function loadWidgetAssets(cfg) {
    if (!assetsLoaded) {
      // The flow's forms are written for Ping's end-user stylesheet.
      loadStyle(cfg.assetsOrigin + "/ux/end-user-nano/0.1.0-alpha.9/end-user-nano.css");
      loadStyle(cfg.assetsOrigin + "/ux/astro-nano/0.1.0-alpha.11/icons.css");
      assetsLoaded = loadScript(cfg.assetsOrigin + "/davinci/latest/v2/davinci.js");
    }
    return assetsLoaded;
  }

  function onFlowSuccess(response) {
    statusLine.textContent = "Signing you in...";
    statusLine.style.display = "";
    fetch("/demo/davinci/complete", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Protection": "1" },
      // Only the JWT that DaVinci signed is sent. The server trusts nothing else.
      body: JSON.stringify({ signedResponse: response && response.signedResponse }),
    })
      .then(function (r) {
        return r.json().then(function (data) { return { ok: r.ok, data: data }; });
      })
      .then(function (result) {
        if (result.ok) {
          window.location.href = "/dashboard.html";
        } else {
          showError(result.data.error || "Sign-in could not be completed");
        }
      })
      .catch(function () { showError("Sign-in could not be completed"); });
  }

  function onFlowError(err) {
    var message = (err && (err.friendlyMessage || err.message)) || "Sign-in was not completed";
    showError(message);
  }

  // method is "runFlow" for a new sign-in and "continueFlow" when DaVinci
  // returns the browser here after the redirect to Authsignal.
  function renderWidget(cfg, method, accessToken, parameters) {
    card.style.display = "none";
    banner.style.display = "none";
    stage.style.display = "block";
    return loadWidgetAssets(cfg).then(function () {
      statusLine.style.display = "none";
      window.davinci.skRenderScreen(document.getElementById("dv-widget"), {
        config: {
          method: method,
          apiRoot: cfg.apiRoot,
          accessToken: accessToken,
          companyId: cfg.companyId,
          policyId: cfg.policyId,
          // DaVinci answers these calls with "Access-Control-Allow-Origin: *",
          // which browsers reject for requests that carry cookies.
          includeHttpCredentials: false,
          parameters: parameters,
        },
        useModal: false,
        successCallback: onFlowSuccess,
        errorCallback: onFlowError,
        onCloseModal: function () {},
      });
    });
  }

  function startSignIn(cfg) {
    statusLine.textContent = "Starting sign-in...";
    statusLine.style.display = "";
    card.style.display = "none";
    stage.style.display = "block";
    fetch("/demo/davinci/start")
      .then(function (r) {
        if (!r.ok) throw new Error("start failed");
        return r.json();
      })
      .then(function (data) { return renderWidget(cfg, "runFlow", data.token, { nonce: data.nonce }); })
      .catch(function () { showError("Could not start sign-in"); });
  }

  function setUpDavinci(cfg) {
    document.getElementById("title").textContent = "Demo App";
    document.getElementById("subtitle").textContent =
      "Sign-in runs through a PingOne DaVinci flow that hands the user to Authsignal.";
    var button = document.getElementById("login-btn");
    button.textContent = "Sign in";
    button.className = "btn btn-primary";
    button.addEventListener("click", function (event) {
      event.preventDefault();
      startSignIn(cfg);
    });
    document.getElementById("dv-cancel").addEventListener("click", function () {
      window.location.href = "/";
    });

    // Back from Authsignal: DaVinci adds a continue token to the return URL.
    var continueToken = params.get("continueToken");
    if (continueToken) {
      history.replaceState(null, "", "/");
      statusLine.textContent = "Finishing sign-in...";
      renderWidget(cfg, "continueFlow", continueToken).catch(function () {
        showError("Could not finish sign-in");
      });
    }
  }

  fetch("/demo/config")
    .then(function (r) { return r.json(); })
    .then(function (cfg) {
      if (cfg.provider === "davinci") setUpDavinci(cfg);
    })
    .catch(function () {});

  fetch("/demo/session")
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.authenticated) {
        window.location.href = "/dashboard.html";
      }
    })
    .catch(function () {});
})();
