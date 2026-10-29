# weglarka-unix-http

HTTP/1.1 client over a unix socket, on hyper: one connection per request, no pooling.
A leaf crate: it depends on nothing from Węglarka, and never on `reqwest` (TCP/TLS clients
live in `weglarka-http`).

- `UnixClient::buffered` sends a request and reads the whole response (status, headers, body),
  with an optional timeout for the exchange.
- `UnixClient::open` returns the response head and a `StreamingResponse` whose body is read frame
  by frame; dropping it closes the connection (the daemon treats that as a cancel).
- `UnixClient::connect` is the raw hyper sender, for special cases.
- `bearer(token)` builds a sensitive `Authorization: Bearer` header value.
- Feature `testing`: `testing::mock`, a mock server on a short temporary socket that records
  method, path, query, `Host`, all headers and the body of every request.

Used by `weglarka-cli`; the admin panel will use it too.
