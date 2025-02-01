{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    rustup
    pkg-config
    openssl
    openssl.dev
    sqlite
    sqlite.dev
    clang
    llvm
    libiconv
    git-lfs
  ];

  LD_LIBRARY_PATH = with pkgs; lib.makeLibraryPath [
    openssl
    sqlite
    stdenv.cc.cc.lib
  ];

  shellHook = ''
    export PATH=$PATH:$HOME/.cargo/bin
    alias vi=nvim
    rustup install nightly
    rustup default nightly
    export RUSTFLAGS="-Z unstable-options"
    export LIBCLANG_PATH="${pkgs.libclang.lib}/lib"
    export LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath [
      pkgs.sqlite
      pkgs.openssl
      pkgs.stdenv.cc.cc.lib
    ]}:$LD_LIBRARY_PATH
    git lfs install
    git lfs pull
  '';
}
