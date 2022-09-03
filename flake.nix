{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }: flake-utils.lib.eachDefaultSystem (system: let
    pkgs = import nixpkgs { inherit system; };
  in {
    packages.default = pkgs.pkgsStatic.rustPlatform.buildRustPackage {
      name = "pfwmark-run";
      src = ./.;
      cargoSha256 = "sha256-sMHwludtMvxjLBRELN8rCodEFuGAZxrXK2qtymzgTuY=";
    };
  });
}