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

// A passive poll whose session has ended normally gets the panel's 286 fragment, which htmx swaps
// in before it stops polling. Behind forward auth the ingress answers first once the identity
// provider's session is gone: a redirect to the sign-in portal on another origin, which the
// browser refuses to follow (the CSP's `connect-src 'self'`, and the portal sends no CORS headers)
// and reports as a network error (htmx:sendError), or a bare 401/403 (htmx:responseError).
// Either way htmx would poll on and keep showing stale data (#444). An element opts in with
// `data-poll-ended="<template id>"` naming the panel's own "session ended" fragment.
function endPoll(elt) {
  var template = document.getElementById(elt.getAttribute("data-poll-ended"));
  if (!template || !elt.isConnected) {
    return;
  }
  // A fresh element without hx-* attributes: htmx stops polling an element that left the page,
  // and never starts on one it was not asked to process.
  var ended = document.createElement("div");
  ended.id = elt.id;
  ended.setAttribute("aria-live", "polite");
  ended.appendChild(template.content.cloneNode(true));
  elt.replaceWith(ended);
}

document.addEventListener("htmx:sendError", function (event) {
  var elt = event.detail && event.detail.elt;
  var path = elt && elt.getAttribute("hx-get");
  if (!path || !elt.hasAttribute("data-poll-ended")) {
    return;
  }
  // The failed request cannot tell a redirect from a dropped connection. Ask again without
  // following redirects: an opaque redirect means the ingress sent the poll away; a real network
  // error (a laptop waking up) changes nothing and the next poll retries.
  fetch(path, {
    method: "GET",
    redirect: "manual",
    credentials: "same-origin",
    cache: "no-store",
    headers: { "HX-Request": "true" },
  }).then(
    function (response) {
      if (response.type === "opaqueredirect" || response.status === 401 || response.status === 403) {
        endPoll(elt);
      }
    },
    function () {},
  );
});

document.addEventListener("htmx:responseError", function (event) {
  var detail = event.detail;
  var elt = detail && detail.elt;
  var status = detail && detail.xhr && detail.xhr.status;
  if (elt && elt.hasAttribute("data-poll-ended") && (status === 401 || status === 403)) {
    endPoll(elt);
  }
});
