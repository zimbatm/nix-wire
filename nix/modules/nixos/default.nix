{ flake, ... }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.nix-wire-record;
  socketDir = "${cfg.store}/var/nix/daemon-socket";
  outputDir = "${cfg.store}/var/nix/nix-wire";
in
{
  options.services.nix-wire-record = {
    enable = lib.mkEnableOption "Nix daemon wire protocol recorder";

    package = lib.mkPackageOption pkgs "nix-wire" {
      default = flake.packages.${pkgs.system}.default;
    };

    store = lib.mkOption {
      type = lib.types.path;
      default = "/nix";
      description = "Nix store root. Socket and recording paths are derived from this.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.nix-wire-record = {
      description = "Nix daemon wire protocol recorder";
      after = [ "nix-daemon.service" ];
      bindsTo = [ "nix-daemon.service" ];
      wantedBy = [ "nix-daemon.service" ];

      serviceConfig = {
        Type = "exec";
        ExecStart = "${lib.getExe' cfg.package "nix-wire-record"} --store ${cfg.store}";
        StateDirectory = "nix-wire-record";

        # Restore socket on stop/crash via ExecStopPost
        ExecStopPost = pkgs.writeShellScript "nix-wire-restore-socket" ''
          socket="${socketDir}/socket"
          orig="${socketDir}/socket.orig"
          if [ -e "$orig" ] && [ ! -e "$socket" ]; then
            mv "$orig" "$socket"
            echo "restored $orig -> $socket"
          fi
        '';

        # Give connections time to drain before SIGKILL
        TimeoutStopSec = 10;

        # Hardening
        ProtectSystem = "strict";
        ReadWritePaths = [
          socketDir
          outputDir
        ];
        PrivateTmp = true;
        NoNewPrivileges = true;
      };
    };
  };
}
