# TLS test fixtures

`test-cert.der` / `test-key.der` are a **throwaway self-signed** ECDSA P-256 certificate and its
private key, used only by `src/ntfy.rs` tests to run a loopback HTTPS server
(`CN=localhost`, SAN `DNS:localhost, IP:127.0.0.1`, valid 100 years). They are deliberately not
trusted anywhere; the test adds them to its own root store.

Regenerate (do not put the PEM files in the repo):

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 36500 \
        -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        -keyout key.pem -out cert.pem
    openssl x509 -in cert.pem -outform der -out test-cert.der
    openssl pkcs8 -topk8 -nocrypt -in key.pem -outform der -out test-key.der
