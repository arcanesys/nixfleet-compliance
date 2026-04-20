# frameworks/dora.nix
#
# DORA (Digital Operational Resilience Act - Regulation 2022/2554).
# Applies to financial entities (credit institutions, investment firms,
# insurance, payment services, crypto-asset service providers).
# Activates controls with DORA-specific defaults.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.frameworks.dora;
  governanceLevel =
    if cfg.criticalProvider
    then "strict"
    else "standard";
  inherit (import ../lib/priorities.nix {inherit lib;}) mkPriority;
  p = mkPriority governanceLevel;
in {
  imports = [
    ../governance/report.nix
    ../compliance-check
    ../controls/_access-control.nix
    ../controls/_asset-inventory.nix
    ../controls/_authentication.nix
    ../controls/_backup-retention.nix
    ../controls/_change-management.nix
    ../controls/_disaster-recovery.nix
    ../controls/_incident-response.nix
    ../controls/_network-segmentation.nix
    ../controls/_vulnerability-mgmt.nix
  ];

  options.compliance.frameworks.dora = {
    enable = lib.mkEnableOption "DORA compliance (Regulation 2022/2554)";

    criticalProvider = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Whether this entity is designated as a critical ICT third-party
        service provider under DORA Art. 31.  Critical providers face
        stricter oversight (lead overseer, enhanced reporting).
      '';
    };

    auditCycle = lib.mkOption {
      type = lib.types.str;
      default =
        if cfg.criticalProvider
        then "hourly"
        else "*-*-* 06:00:00";
      description = ''
        Evidence collection frequency.
        Critical providers: hourly (continuous monitoring).
        Others: daily at 06:00.
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
      architecture = p pkgs.stdenv.hostPlatform.parsed.cpu.name;
    };

    compliance.controls = {
      # Art. 9 - ICT access control policies
      accessControl = {
        enable = true;
        passwordAuthDisabled = p true;
        rootLoginDisabled = p true;
        idleTimeoutMinutes = p (
          if cfg.criticalProvider
          then 15
          else 30
        );
      };

      # Art. 8 - ICT asset management
      assetInventory.enable = true;

      # Art. 9 - Authentication
      authentication = {
        enable = true;
        mfaRequired = p cfg.criticalProvider;
      };

      # Art. 12 - Backup and recovery
      backupRetention = {
        enable = true;
        retentionDays = p (
          if cfg.criticalProvider
          then 730
          else 365
        );
        verifyInterval = p (
          if cfg.criticalProvider
          then "daily"
          else "weekly"
        );
      };

      # Art. 8 - Change and patch management
      changeManagement = {
        enable = true;
        maxSystemAgeDays = p (
          if cfg.criticalProvider
          then 14
          else 30
        );
      };

      # Art. 12 - Business continuity and disaster recovery
      disasterRecovery = {
        enable = true;
        minGenerations = p (
          if cfg.criticalProvider
          then 10
          else 5
        );
        rtoTarget = p (
          if cfg.criticalProvider
          then "4h"
          else "24h"
        );
        testInterval = p (
          if cfg.criticalProvider
          then "monthly"
          else "quarterly"
        );
      };

      # Art. 17 - ICT-related incident management
      incidentResponse = {
        enable = true;
        alertRetentionDays = p 365;
        rollbackTestInterval = p (
          if cfg.criticalProvider
          then "weekly"
          else "monthly"
        );
      };

      # Art. 9 - Network segmentation
      networkSegmentation = {
        enable = true;
        requireFirewall = p true;
      };

      # Art. 8 - Vulnerability and patch management
      vulnerabilityMgmt = {
        enable = true;
        scanInterval = p (
          if cfg.criticalProvider
          then "daily"
          else "weekly"
        );
        maxNixpkgsAgeDays = p (
          if cfg.criticalProvider
          then 14
          else 30
        );
        blockOnCritical = p cfg.criticalProvider;
      };
    };

    compliance.evidence.collector.interval = p cfg.auditCycle;
    compliance.check.enable = lib.mkDefault true;
  };
}
