{ lib
, system
, fetchurl
, stdenv
, autoPatchelfHook
, glibc
}:

# Installs the prebuilt `vaultwarden-cli` release artifact (fast path, no
# compilation). Artifacts are published by the GitHub release CI as
# `vaultwarden-cli-<target>.tar.gz` for the Linux targets.

let
  # Centralized per-platform mapping: Nix system -> release artifact.
  # `target` is the Rust release target, `hash` is the sha256 (SRI) of the
  # published tarball for v0.5.4.
  artifacts = {
    x86_64-linux = {
      target = "x86_64-unknown-linux-gnu";
      url = "https://github.com/haydonryan/vaultwarden-cli/releases/download/v0.5.4/vaultwarden-cli-x86_64-unknown-linux-gnu.tar.gz";
      hash = "sha256-jnuWTGh9KGSAkdpKGE9/TaK6wEpJARptfr2lM5FxHtQ=";
    };
    aarch64-linux = {
      target = "aarch64-unknown-linux-gnu";
      url = "https://github.com/haydonryan/vaultwarden-cli/releases/download/v0.5.4/vaultwarden-cli-aarch64-unknown-linux-gnu.tar.gz";
      hash = "sha256-2bFwYLOk7UzXMzIwwI1GauSm0mJ67lMXk8XDEZHV2Nc=";
    };
  };

  art = artifacts.${system} or (throw ''
    vaultwarden-cli: app-bin is unsupported on system "${system}".
    Supported systems: ${lib.concatStringsSep ", " (lib.attrNames artifacts)}.
  '');
in
stdenv.mkDerivation {
  pname = "vaultwarden-cli";
  version = "0.5.4";

  src = fetchurl {
    url = art.url;
    sha256 = art.hash;
  };

  # The release tarball contains a single flat file (no top-level directory).
  sourceRoot = ".";

  # The glibc build dynamically links glibc/libgcc (libc, libm, libgcc_s), so
  # rewrite its interpreter and library paths for the Nix store. This is a
  # no-op if the artifact were ever fully static.
  nativeBuildInputs = [ autoPatchelfHook ];
  buildInputs = [ glibc stdenv.cc.cc.lib ];

  installPhase = ''
    runHook preInstall
    install -Dm755 vaultwarden-cli $out/bin/vaultwarden-cli
    runHook postInstall
  '';

  meta = with lib; {
    description = "CLI client for Vaultwarden - retrieve secrets for batch files and environment variables (prebuilt release)";
    homepage = "https://github.com/haydonryan/vaultwarden-cli";
    license = licenses.mit;
    mainProgram = "vaultwarden-cli";
    platforms = [ "x86_64-linux" "aarch64-linux" ];
  };
}
