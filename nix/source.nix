{ lib
, rustPlatform
, src
, pkg-config
, dbus
, openssl
}:

# Builds `vaultwarden-cli` from source. `src` is the flake source (the whole
# repository); the single crate's Cargo files are consumed.
rustPlatform.buildRustPackage {
  pname = "vaultwarden-cli";
  version = "0.5.4";

  inherit src;

  # The committed Cargo.lock is used with --locked, so the build resolves no
  # dependencies from the network; everything comes from the Nix store.
  cargoLock = {
    lockFile = ./../Cargo.lock;
  };

  # The crate's Linux keyring store links against libdbus and (via
  # dbus-secret-service) OpenSSL, both discovered through pkg-config.
  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ dbus openssl ];

  # Skip the `cargo test` check phase: several tests exercise the keyring /
  # D-Bus Secret Service and live servers that are unavailable in the Nix
  # build sandbox. The full suite runs via `just test` / CI on a real host.
  doCheck = false;

  meta = with lib; {
    description = "CLI client for Vaultwarden - retrieve secrets for batch files and environment variables";
    homepage = "https://github.com/haydonryan/vaultwarden-cli";
    license = licenses.mit;
    mainProgram = "vaultwarden-cli";
    platforms = [ "x86_64-linux" "aarch64-linux" ];
  };
}
