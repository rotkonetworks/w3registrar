{
  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils, naersk }:
    utils.lib.eachDefaultSystem (system:
      let
        unstable = import <nixpkgs-unstable> {};
        naersk-lib = pkgs.callPackage naersk { };

        rust_overlay = import (builtins.fetchTarball "https://github.com/oxalica/rust-overlay/archive/master.tar.gz");
        pkgs = import <nixpkgs> { overlays = [ rust_overlay ]; };
        rustVersion = "1.81.0";
        rust = pkgs.rust-bin.stable.${rustVersion}.default.override {
        extensions = [
          "rust-src" # for rust-analyzer
          "rustc"
          "cargo"
        ];};
      in
      {
        defaultPackage = naersk-lib.buildPackage ./.;
        devShell = with pkgs; mkShell {
          buildInputs = [ rust pkg-config openssl shim-unsigned subxt ];
        };
      });
}
