# Crypto Dependency Duplicates

## Overview

`cargo tree -d` and `cargo deny check` report duplicate versions of several
cryptography crates in the dependency tree. All of the duplicates originate
from the Linux-only keyring dependency chain:

```
vaultwarden-cli
├── aes 0.9.1, cbc 0.2.1, cipher 0.5.2, digest 0.11.3, …  (direct)
└── dbus-secret-service-keyring-store v1.0.0
    └── dbus-secret-service v4.1.0
        ├── aes 0.8.4, cbc 0.1.2, cipher 0.4.4, digest 0.10.7, …  (internal)
        ├── hkdf 0.12.4, hmac 0.12.1, sha2 0.10.9
        └── block-buffer 0.10.4, block-padding 0.3.3, …
```

## Root Cause

`dbus-secret-service-keyring-store` v1.0.0 depends on
`dbus-secret-service` v4.1.0. This version of `dbus-secret-service` pins
its own set of crypto dependencies at older semver-incompatible versions
(e.g. `aes 0.8` vs the project's `aes 0.9`).

Both crates are at their **latest published versions** as of 2026-07-27:
- `dbus-secret-service-keyring-store` = 1.0.0
- `dbus-secret-service` = 4.1.0

Until one or both upstream crates cut a new release that migrates to the
newer crypto crate versions, these duplicates cannot be eliminated from
the dependency tree.

## Impact

- **Build surface**: The older crates add ~10–15 extra crate compilations
  on Linux-only builds. On macOS and Windows this entire chain is absent.
- **Binary size**: Minimal — the extra code is segregated inside the
  dbus secret service transport and does not duplicate vault crypto
  operations.
- **Runtime**: No behavioral conflict. The two stacks are linked
  independently: one is used internally by the keyring store for its
  own D-Bus transport, the other by vaultwarden-cli for vault data
  crypto (AES-CBC decryption, HKDF key derivation, HMAC verification,
  SHA-256 hashing, etc.).

## Configuration

The `deny.toml` `[bans]` section lists every skipped duplicate crate
with its version and an explanatory comment. When the upstream crates
update their dependency ranges, the skips should be removed and the
duplicate warnings should be treated as actionable.

## Revisit criteria

Remove the `[bans]` skip entries and verify no duplicates remain when:
1. `dbus-secret-service-keyring-store` >= 2.0.0 is published, OR
2. `dbus-secret-service` >= 5.0.0 is published with updated crypto deps.
