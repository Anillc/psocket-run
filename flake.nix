{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }: flake-utils.lib.eachDefaultSystem (system: let
    pkgs = import nixpkgs { inherit system; };
  in {
    packages.default = pkgs.pkgsStatic.rustPlatform.buildRustPackage {
      name = "psocket-run";
      src = ./.;
      cargoSha256 = "sha256-HOSQlylOX8y6MYGkPtqHjmL/HLNtgcqfxk9oBA3ZHJI=";
    };
  });
}