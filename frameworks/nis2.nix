# frameworks/nis2.nix
#
# NIS2 Directive (2022/2555) compliance framework.
# Activates controls with NIS2-specific defaults.
# Differentiates between "essential" and "important" entity types.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.frameworks.nis2;
  isEssential = cfg.entityType == "essential";
  governanceLevel =
    if isEssential
    then "strict"
    else "standard";
  inherit (import ../lib/priorities.nix {inherit lib;}) mkPriority;
  p = mkPriority governanceLevel;
in {
  imports = [
    ../governance/report.nix
    ../compliance-check
    ../controls/_supply-chain.nix
    ../controls/_asset-inventory.nix
    ../controls/_encryption-at-rest.nix
    ../controls/_access-control.nix
    ../controls/_baseline-hardening
    ../controls/_audit-logging
    ../controls/_backup-retention.nix
    ../controls/_encryption-in-transit.nix
    ../controls/_incident-response.nix
    ../controls/_disaster-recovery.nix
    ../controls/_vulnerability-mgmt.nix
    ../controls/_authentication.nix
  ];

  options.compliance.frameworks.nis2 = {
    enable = lib.mkEnableOption "NIS2 directive compliance (Directive 2022/2555)";

    entityType = lib.mkOption {
      type = lib.types.enum ["essential" "important"];
      default = "important";
      description = ''
        NIS2 entity classification.
        Essential: energy, transport, banking, health, water, digital infra,
                   ICT service management, public admin, space.
        Important: postal, waste, chemicals, food, manufacturing, digital
                   providers, research.
        Essential entities face stricter audit obligations.
      '';
    };

    auditCycle = lib.mkOption {
      type = lib.types.str;
      default =
        if isEssential
        then "hourly"
        else "*-*-* 06:00:00";
      description = ''
        Systemd calendar expression for evidence collection frequency.
        Essential: hourly (continuous monitoring).
        Important: daily at 06:00 (periodic assessment).
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    compliance.governance = {
      # mkDefault (not `p`) — enforceMode is a user policy knob, not a
      # strictness-derived value. All frameworks set "enforce"; consumers
      # override with a plain set (e.g. enforceMode = "report").
      enforceMode = lib.mkDefault "enforce";
      level = p governanceLevel;
      architecture = lib.mkDefault pkgs.stdenv.hostPlatform.parsed.cpu.name;
    };

    compliance.controls = {
      supplyChain = {
        enable = true;
        sbomGeneration = p true;
        inputStalenessWarningDays = p (
          if isEssential
          then 14
          else 30
        );
      };

      assetInventory.enable = true;

      encryptionAtRest = {
        enable = true;
        requireEncryptedSwap = p true;
        requireTmpOnTmpfs = p true;
      };

      accessControl = {
        enable = true;
        passwordAuthDisabled = p true;
        rootLoginDisabled = p true;
        idleTimeoutMinutes = p (
          if isEssential
          then 15
          else 30
        );
      };

      baselineHardening.enable = true;

      auditLogging = {
        enable = true;
        retentionDays = p (
          if isEssential
          then 730
          else 365
        );
      };

      backupRetention = {
        enable = true;
        retentionDays = p (
          if isEssential
          then 730
          else 365
        );
        verifyInterval = p (
          if isEssential
          then "daily"
          else "weekly"
        );
      };

      encryptionInTransit = {
        enable = true;
        minTlsVersion = p "1.2";
        certExpiryWarningDays = p (
          if isEssential
          then 30
          else 60
        );
      };

      incidentResponse = {
        enable = true;
        alertRetentionDays = p 365;
        rollbackTestInterval = p (
          if isEssential
          then "weekly"
          else "monthly"
        );
      };

      disasterRecovery = {
        enable = true;
        minGenerations = p (
          if isEssential
          then 10
          else 5
        );
        rtoTarget = p (
          if isEssential
          then "4h"
          else "24h"
        );
        testInterval = p (
          if isEssential
          then "monthly"
          else "quarterly"
        );
      };

      vulnerabilityMgmt = {
        enable = true;
        scanInterval = p (
          if isEssential
          then "daily"
          else "weekly"
        );
        maxNixpkgsAgeDays = p (
          if isEssential
          then 14
          else 30
        );
        blockOnCritical = p isEssential;
      };

      authentication = {
        enable = true;
        mfaRequired = p isEssential;
      };
    };

    compliance.evidence.collector.interval = p cfg.auditCycle;
    compliance.check.enable = lib.mkDefault true;
  };
}
