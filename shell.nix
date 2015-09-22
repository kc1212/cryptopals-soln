{ nixpkgs ? import <nixpkgs> {}, compiler ? "ghc7102" }:
let
  inherit (nixpkgs) pkgs;
  ghc = pkgs.haskell.packages.${compiler}.ghcWithPackages (ps: with ps;
    [mtl random byteable cipher-aes base64-bytestring base16-bytestring split]);

in
pkgs.stdenv.mkDerivation {
  name = "matasano";
  buildInputs = [ ghc ];
  shellHook = "eval $(egrep ^export ${ghc}/bin/ghc)";
}

