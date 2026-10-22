// Small progressive enhancements. The site works without JavaScript.
(function () {
  "use strict";

  // Scan form: trim input, block empty submits, show a busy state.
  var scanForm = document.getElementById("scan-form");
  if (scanForm) {
    var input = scanForm.querySelector("input[name='url']");
    var button = document.getElementById("scan-btn");
    var idleLabel = button ? button.textContent : "";

    scanForm.addEventListener("submit", function (event) {
      input.value = input.value.trim();
      if (!input.value) {
        event.preventDefault();
        input.focus();
        return;
      }
      if (button) {
        button.disabled = true;
        button.textContent = "Scanning…";
      }
    });

    // Restore the button if the user comes back via the browser's back button.
    window.addEventListener("pageshow", function () {
      if (button) {
        button.disabled = false;
        button.textContent = idleLabel;
      }
    });
  }

  // Any form with data-confirm asks before submitting.
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.dataset.confirm)) {
        event.preventDefault();
      }
    });
  });

  // Show scan times in the visitor's local timezone (history and result pages).
  var isoPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;
  document.querySelectorAll("td, dd").forEach(function (el) {
    var text = el.textContent.trim();
    if (el.children.length === 0 && isoPattern.test(text)) {
      var date = new Date(text);
      if (!isNaN(date)) {
        el.title = text;
        el.textContent = date.toLocaleString();
      }
    }
  });
})();