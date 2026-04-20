# frameworks/iso27001.nix
#
# ISO/IEC 27001:2022 - Information security management systems.
# Activates controls mapped to Annex A controls.
# Covers 14 of 16 available controls (all except network-segmentation
# and secure-boot which map to other frameworks).
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.frameworks.iso27001;
  isFull = cfg.certificationScope == "full";
  governanceLevel =
    if isFull
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
    ../controls/_audit-logging
    ../controls/_authentication.nix
    ../controls/_backup-retention.nix
    ../controls/_baseline-hardening
    ../controls/_change-management.nix
    ../controls/_disaster-recovery.nix
    ../controls/_encryption-at-rest.nix
    ../controls/_encryption-in-transit.nix
    ../controls/_incident-response.nix
    ../controls/_key-management.nix
    ../controls/_supply-chain.nix
    ../controls/_vulnerability-mgmt.nix
  ];

  options.compliance.frameworks.iso27001 = {
    enable = lib.mkEnableOption "ISO/IEC 27001:2022 compliance";

    certificationScope = lib.mkOption {
      type = lib.types.enum ["full" "partial"];
      default = "full";
      description = ''
        Certification scope.
        Full: all applicable Annex A controls enforced with strict defaults.
        Partial: controls enabled with relaxed defaults (pre-certification posture).
      '';
    };

    auditCycle = lib.mkOption {
      type = lib.types.str;
      default =
        if isFull
        then "hourly"
        else "*-*-* 06:00:00";
      description = ''
        Evidence collection frequency.
        Full scope: hourly (continuous monitoring for certification evidence).
        Partial: daily at 06:00.
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
      # A.8.2/A.8.3 - Privileged access rights / Information access restriction
      accessControl = {
        enable = true;
        passwordAuthDisabled = p true;
        rootLoginDisabled = p true;
        idleTimeoutMinutes = p (
          if isFull
          then 15
          else 30
        );
      };

      # A.5.9 - Inventory of information and other associated assets
      assetInventory.enable = true;

      # A.8.15/A.8.16 - Logging / Monitoring activities
      auditLogging = {
        enable = true;
        retentionDays = p (
          if isFull
          then 730
          else 365
        );
      };

      # A.8.5 - Secure authentication
      authentication = {
        enable = true;
        mfaRequired = p isFull;
      };

      # A.8.13 - Information backup
      backupRetention = {
        enable = true;
        retentionDays = p (
          if isFull
          then 730
          else 365
        );
        verifyInterval = p (
          if isFull
          then "daily"
          else "weekly"
        );
      };

      # A.8.9/A.8.8 - Configuration management / Technical vulnerability management
      baselineHardening.enable = true;

      # A.8.32 - Change management
      changeManagement = {
        enable = true;
        maxSystemAgeDays = p (
          if isFull
          then 14
          else 30
        );
      };

      # A.5.29/A.5.30 - Information security during disruption / ICT readiness for business continuity
      disasterRecovery = {
        enable = true;
        minGenerations = p (
          if isFull
          then 10
          else 5
        );
        rtoTarget = p (
          if isFull
          then "4h"
          else "24h"
        );
        testInterval = p (
          if isFull
          then "monthly"
          else "quarterly"
        );
      };

      # A.8.24 - Use of cryptography (at rest)
      encryptionAtRest = {
        enable = true;
        requireEncryptedSwap = p true;
        requireTmpOnTmpfs = p true;
      };

      # A.8.20/A.8.24 - Networks security / Use of cryptography (in transit)
      encryptionInTransit = {
        enable = true;
        minTlsVersion = p "1.2";
        certExpiryWarningDays = p (
          if isFull
          then 30
          else 60
        );
      };

      # A.5.24/A.5.26 - Incident management planning / Response to incidents
      incidentResponse = {
        enable = true;
        alertRetentionDays = p 365;
        rollbackTestInterval = p (
          if isFull
          then "weekly"
          else "monthly"
        );
      };

      # A.8.24 - Use of cryptography (key management)
      keyManagement = {
        enable = true;
        maxKeyAgeDays = p (
          if isFull
          then 365
          else 730
        );
      };

      # A.5.19/A.5.21 - Information security in supplier relationships / ICT supply chain
      supplyChain = {
        enable = true;
        sbomGeneration = p true;
        inputStalenessWarningDays = p (
          if isFull
          then 14
          else 30
        );
      };

      # A.8.8 - Management of technical vulnerabilities
      vulnerabilityMgmt = {
        enable = true;
        scanInterval = p (
          if isFull
          then "daily"
          else "weekly"
        );
        maxNixpkgsAgeDays = p (
          if isFull
          then 14
          else 30
        );
        blockOnCritical = p isFull;
      };
    };

    compliance.evidence.collector.interval = p cfg.auditCycle;
    compliance.check.enable = lib.mkDefault true;
  };
}
