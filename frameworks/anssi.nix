# frameworks/anssi.nix
#
# ANSSI Linux hardening guide v2.0 compliance framework.
# Maps ANSSI compliance levels and system categories to
# governance settings and enables hardening controls.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.frameworks.anssi;
  isServer = cfg.category == "server";
in {
  imports = [
    ../governance/report.nix
    ../compliance-check
    ../controls/_baseline-hardening
    ../controls/_audit-logging
    ../controls/_access-control.nix
    ../controls/_encryption-at-rest.nix
    ../controls/_authentication.nix
    ../controls/_secure-boot.nix
    ../controls/_network-segmentation.nix
  ];

  options.compliance.frameworks.anssi = {
    enable = lib.mkEnableOption "ANSSI Linux hardening guide v2.0 compliance";

    level = lib.mkOption {
      type = lib.types.enum ["minimal" "intermediary" "reinforced" "high"];
      default = "intermediary";
      description = ''
        ANSSI compliance level.
        - minimal: basic hygiene
        - intermediary: standard production hardening (default)
        - reinforced: aggressive hardening
        - high: maximum security (may break workloads)
      '';
    };

    category = lib.mkOption {
      type = lib.types.enum ["base" "client" "server"];
      default = "server";
      description = ''
        ANSSI system category.
        - base: rules that apply to all systems
        - client: workstation-specific rules
        - server: server-specific rules
      '';
    };

    exceptions = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule {
        options.rationale = lib.mkOption {
          type = lib.types.str;
          description = "Mandatory explanation for excepting this rule";
        };
      });
      default = {};
      description = "Per-rule exceptions with mandatory rationale (e.g., NixOS limitations)";
    };
  };

  config = lib.mkIf cfg.enable (let
    levelToGovernance = {
      "minimal" = "minimal";
      "intermediary" = "standard";
      "reinforced" = "strict";
      "high" = "paranoid";
    };
    hostTypeFromCategory = {
      "base" = "server";
      "client" = "workstation";
      "server" = "server";
    };
    governanceLevel = levelToGovernance.${cfg.level};
    inherit (import ../lib/priorities.nix {inherit lib;}) mkPriority;
    p = mkPriority governanceLevel;
  in {
    compliance.governance = {
      # mkDefault (not `p`) — enforceMode is a user policy knob, not a
      # strictness-derived value. All frameworks set "enforce"; consumers
      # override with a plain set (e.g. enforceMode = "report").
      enforceMode = lib.mkDefault "enforce";
      level = p governanceLevel;
      hostType = lib.mkDefault hostTypeFromCategory.${cfg.category};
      exceptions = lib.mkDefault (lib.mapAttrs (_: v: {inherit (v) rationale;}) cfg.exceptions);
      architecture = lib.mkDefault pkgs.stdenv.hostPlatform.parsed.cpu.name;
    };

    compliance.controls = {
      baselineHardening.enable = true;
      auditLogging = {
        enable = true;
        retentionDays = p 365;
      };
      accessControl = {
        enable = true;
        passwordAuthDisabled = p true;
        rootLoginDisabled = p true;
        idleTimeoutMinutes = p (
          if isServer
          then 15
          else 30
        );
      };
      encryptionAtRest.enable = true;
      authentication.enable = true;
      secureBoot.enable = true;
      networkSegmentation = lib.mkIf isServer {
        enable = true;
        requireFirewall = p true;
      };
    };

    compliance.evidence.collector.interval = p "hourly";
    compliance.check.enable = lib.mkDefault true;
  });
}
