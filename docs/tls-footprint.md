# TLS Footprint

The CLI uses `reqwest` with `native-tls`, `json`, and `form`, with
`default-features = false`.

This keeps `reqwest` certificate verification enabled through the platform TLS
stack while avoiding the previous `rustls-platform-verifier` graph. Server URL
validation is still enforced in `ApiClient::new_with_flags`: HTTPS is required
unless the caller explicitly opts into insecure HTTP with
`--allow-insecure-http` or `VAULTWARDEN_ALLOW_HTTP=1`.

Measured on Linux in release mode:

| Configuration | Runtime TLS graph | Release binary |
| --- | --- | ---: |
| `rustls-no-provider` plus explicit `rustls` ring provider | `rustls-platform-verifier`, `rustls-native-certs`, `rustls-webpki`, `webpki-root-certs` | 5,933,400 bytes |
| `native-tls` | `native-tls`, `hyper-tls`, `tokio-native-tls`, system OpenSSL on Linux | 4,630,840 bytes |

The kept configuration is 1,302,560 bytes smaller and removes
`rustls-platform-verifier` from the default dependency tree. The all-target
duplicate graph still contains `windows-sys` 0.59 and 0.61 through non-TLS
dependencies, but the `windows-sys` 0.52 path from `ring` and the
`rustls-platform-verifier` Windows paths are gone.
