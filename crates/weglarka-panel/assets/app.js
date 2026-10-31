// Panel behaviour that needs a script. Everything here runs under the strict CSP: no inline
// handlers, no eval. Alpine's CSP build only evaluates simple property references.
document.addEventListener("alpine:init", function () {
  // The log viewer: "wrap long lines" is a local, per-page toggle.
  Alpine.data("logView", function () {
    return { wrap: false };
  });
});

// A log left open on a chatty app must not grow the page without bound: keep the newest lines.
// htmx-ext-sse swaps a message in and then triggers htmx:sseMessage on the swap target.
var KEEP_ROWS = { log: 2000, "access-rows": 1000 };
document.addEventListener("htmx:sseMessage", function (event) {
  var target = event.target;
  var keep = target && KEEP_ROWS[target.id];
  if (keep) {
    while (target.childElementCount > keep) {
      target.removeChild(target.firstElementChild);
    }
  }
});

// htmx does not swap a 4xx by default. A refused access-log filter answers 400 with a fixed
// message, which is exactly what the form should show.
document.addEventListener("htmx:beforeSwap", function (event) {
  var detail = event.detail;
  if (detail.xhr && detail.xhr.status === 400 && detail.target && detail.target.id === "access-live") {
    detail.shouldSwap = true;
    detail.isError = false;
  }
});
