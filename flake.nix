{
  inputs.rust-overlay.url = "github:oxalica/rust-overlay";
  inputs.naersk.url = "github:nix-community/naersk";

  outputs = {
    self, nixpkgs, flake-utils, rust-overlay, naersk
  }: flake-utils.lib.eachDefaultSystem (system: let
    pkgs = import nixpkgs {
      inherit system;
      overlays = [ (import rust-overlay) ];
    };
    rust = pkgs.rust-bin.beta.latest.default;
    naersk' = pkgs.callPackage naersk {
      cargo = rust;
      rustc = rust;
    };
  in {
    packages.default = naersk'.buildPackage { src = ./.; };
    devShells.default = pkgs.mkShell {
      nativeBuildInputs = with pkgs; [ rust ];
    };
  });
}