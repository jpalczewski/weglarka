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
document.addEventListener("htmx:sseMessage", function (event) {
  var target = event.target;
  if (target && target.id === "log") {
    while (target.childElementCount > 2000) {
      target.removeChild(target.firstElementChild);
    }
  }
});
