# TLS Footprint

The CLI uses `reqwest` with `rustls-no-provider`, `json`, and `form`, with
`default-features = false`. It enables the `rustls` `ring` provider explicitly.

This keeps `reqwest` certificate verification enabled without requiring target
OpenSSL development files for Linux cross-release builds. Server URL validation
is still enforced in `ApiClient::new_with_flags`: HTTPS is required unless the
caller explicitly opts into insecure HTTP with
`--allow-insecure-http` or `VAULTWARDEN_ALLOW_HTTP=1`.

Measured on Linux in release mode:

| Configuration | Runtime TLS graph | Release binary |
| --- | --- | ---: |
| `rustls-no-provider` plus explicit `rustls` ring provider | `rustls-platform-verifier`, `rustls-native-certs`, `rustls-webpki`, `webpki-root-certs` | 5,933,400 bytes |
| `native-tls` | `native-tls`, `hyper-tls`, `tokio-native-tls`, system OpenSSL on Linux | 4,630,840 bytes |

`native-tls` is smaller on the native Linux build, but it depends on OpenSSL on
Linux and breaks the portable cross-release targets unless the cross image also
has target OpenSSL headers and pkg-config metadata. The kept configuration is
larger but avoids that native system dependency in release CI.
