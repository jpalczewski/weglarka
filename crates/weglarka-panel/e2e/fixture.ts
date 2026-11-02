// A stand-in for the panel behind forward auth, for the browser tests. It serves the app page's
// "Resources" section cut from the real template (so the markup cannot drift from the panel's),
// `app.js` and the vendored htmx, with the panel's Content-Security-Policy. `/__mode` switches what
// the ingress answers the stats poll with; a second server is the sign-in portal on another
// origin, which sends no CORS headers (like a real one); the CSP's `connect-src 'self'` and the
// missing CORS headers make a followed redirect fail in the browser, as it does in production.
import { readFileSync } from "node:fs";
import { join } from "node:path";

const port = Number(process.env.FIXTURE_PORT ?? 4173);
const portalPort = Number(process.env.PORTAL_PORT ?? port + 1);
const panel = join(import.meta.dir, "..");

const read = (path: string) => readFileSync(join(panel, path), "utf8");
const csp = /CONTENT_SECURITY_POLICY_VALUE: &str = "([^"]+)"/.exec(read("src/headers.rs"))?.[1];
if (!csp) throw new Error("cannot find the panel's CSP in src/headers.rs");

const vendored = read("assets/vendor/VENDORED.md");
const htmx = /htmx-\d+\.\d+\.\d+\.min\.js/.exec(vendored)?.[0];
if (!htmx) throw new Error("cannot find the vendored htmx in VENDORED.md");

// htmx settings exactly as the panel's base layout sets them (no injected styles under the CSP).
const base = read("templates/base.html");
const htmxConfig = /<meta name="htmx-config"[^>]*>/.exec(base)?.[0];
if (!htmxConfig) throw new Error("cannot find the htmx-config meta in templates/base.html");

// The section between the Resources heading's <section> and its end, with the askama bits filled.
const template = read("templates/app.html");
const section = /<section aria-labelledby="h-stats">[\s\S]*?<\/section>/.exec(template)?.[0];
if (!section) throw new Error("cannot find the Resources section in templates/app.html");
const ended = read("templates/poll_ended.html").trimEnd();
const markup = section
  .replaceAll("{{ app.name }}", "web")
  .replace('{% include "poll_ended.html" %}', ended)
  // Ten seconds would make every test slow; the cadence is not what is under test.
  .replace("every 10s", "every 300ms");
if (/\{[{%]/.test(markup)) throw new Error(`unfilled template syntax left: ${markup}`);

const page = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>fixture</title>
${htmxConfig}
<script src="/static/${htmx}" defer></script>
<script src="/static/app.js" defer></script>
</head><body><main>${markup}</main></body></html>`;

type Mode = "ok" | "redirect" | "unauthorized" | "forbidden";
let mode: Mode = "ok";
let polls = 0;

const html = (body: string, status = 200) =>
  new Response(body, {
    status,
    headers: { "content-type": "text/html; charset=utf-8", "content-security-policy": csp },
  });

Bun.serve({
  port,
  hostname: "127.0.0.1",
  fetch(request) {
    const url = new URL(request.url);
    switch (url.pathname) {
      case "/__health":
        return new Response("ok");
      case "/__mode":
        mode = (url.searchParams.get("m") as Mode) ?? "ok";
        polls = 0;
        return new Response(mode);
      case "/__polls":
        return new Response(String(polls));
      case "/":
        return html(page);
      case "/static/app.js":
        return new Response(read("assets/app.js"), { headers: { "content-type": "text/javascript" } });
      case `/static/${htmx}`:
        return new Response(read(`assets/vendor/${htmx}`), {
          headers: { "content-type": "text/javascript" },
        });
      case "/apps/web/stats":
        polls += 1;
        switch (mode) {
          case "ok":
            return html(`<p class="muted">Sampled poll ${polls}. Updates every 10 seconds.</p>`);
          case "redirect":
            // What nginx sends when the provider's forward-auth check fails.
            return new Response(null, {
              status: 302,
              headers: { location: `http://localhost:${portalPort}/?rd=${encodeURIComponent(request.url)}` },
            });
          case "unauthorized":
            return new Response("Unauthorized", { status: 401 });
          case "forbidden":
            return new Response("Forbidden", { status: 403 });
        }
    }
    return new Response("not found", { status: 404 });
  },
});

// The sign-in portal: another origin, no CORS headers.
Bun.serve({
  port: portalPort,
  hostname: "127.0.0.1",
  fetch: () => html("<p>Sign in</p>"),
});

console.log(`fixture on http://127.0.0.1:${port}, portal on http://localhost:${portalPort}`);
