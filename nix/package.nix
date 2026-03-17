{
  pkgs,
  ...
}:
pkgs.rustPlatform.buildRustPackage {
  pname = "nix-wire";
  version = "0.1.0";
  src = ../.;
  cargoLock.lockFile = ../Cargo.lock;
}
