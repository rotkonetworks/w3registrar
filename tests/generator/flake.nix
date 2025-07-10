{
  inputs = {
    utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };
  outputs =
    {
      self,
      nixpkgs,
      utils,
    }:
    utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShell = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
          postgresql
          python3
          python3Packages.python-lsp-server
          python3Packages.pip
          python3Packages.virtualenv
          ];
          buildInputs = with pkgs; [ ];
          shellHook = ''
            echo "Hello There"
            python -m venv venv
          '';
        };
      }
    );
}
