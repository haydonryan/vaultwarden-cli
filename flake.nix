{
  description = "Nix packaging for vaultwarden-cli (prebuilt app-bin and from-source app-src)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      # Systems this flake supports. These are the Linux platforms for which
      # prebuilt release artifacts are published.
      systems = [ "x86_64-linux" "aarch64-linux" ];

      # Apply a function to each supported system, keyed by system name.
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);

      # A nixpkgs instantiation per system.
      pkgsFor = system: import nixpkgs { inherit system; };
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          # Prebuilt release artifact (fast, no compilation).
          app-bin = pkgs.callPackage ./nix/binary.nix { inherit system; };
          # Build the executable from source via the committed Cargo.lock.
          app-src = pkgs.callPackage ./nix/source.nix { src = self; };
        in
        {
          inherit app-bin app-src;
          default = app-bin;
        });

      devShells = forAllSystems (system:
        let
          pkgs = pkgsFor system;
        in
        {
          # Focused shell for hacking on the CLI: Rust toolchain plus the
          # native libraries the crate links against (dbus, openssl) so
          # `cargo build` works out of the box.
          default = pkgs.mkShell {
            packages = with pkgs; [
              cargo
              clippy
              rustc
              rustfmt
              pkg-config
              dbus
              openssl
            ];
          };
        });
    };
}
