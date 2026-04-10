(function () {
  var params = new URLSearchParams(window.location.search);
  var error = params.get("error");
  if (error) {
    var banner = document.getElementById("error-banner");
    banner.textContent = error;
    banner.style.display = "block";
    history.replaceState(null, "", "/");
  }

  fetch("/demo/session")
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.authenticated) {
        window.location.href = "/dashboard.html";
      }
    })
    .catch(function () {});
})();
