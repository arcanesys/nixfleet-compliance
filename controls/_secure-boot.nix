# controls/_secure-boot.nix
#
# Secure boot - CRA Art. 10, SecNumCloud.
# No enforcement: secure boot setup is via lanzaboote, handled by fleet.
# Verifies: EFI support, secure boot status, boot loader detection,
# signed unified kernel images.
#
# Typed control: type="both". The static gate inspects whether a
# secure-boot enabling layer (lanzaboote, sd-stub with shim) is
# wired in NixOS config. The runtime probe checks bootctl/EFI state
# and refuses to lie when secure boot is off - historically the
# probe shorted to `compliant=true` when `cfg.requireSecureBoot=false`,
# turning the entire control into a no-op (issue #10). Operators
# who can't run secure boot should disable the control entirely
# (`compliance.controls.secureBoot.enable = false`) rather than
# enabling it without enforcement.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.secureBoot;
  gov = config.compliance.governance;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
  framework = gov.primaryFramework or "dora";
  schemaVersion =
    config.compliance.schemaVersions.${framework}
    or (throw "compliance.schemaVersions.${framework} is not set");

  systemdBootEnabled = config.boot.loader.systemd-boot.enable or false;
  grubEnabled = config.boot.loader.grub.enable or false;
  declaredBootLoader =
    if systemdBootEnabled
    then "systemd-boot"
    else if grubEnabled
    then "grub"
    else "unknown";
  configurationLimit = config.boot.loader.systemd-boot.configurationLimit or null;

  # Secure-boot-enabling layers, declared in NixOS. The presence of
  # any of these is the static signal that this host is *trying* to
  # run secure boot - `bootctl status` confirms it actually does at
  # runtime.
  #
  # `boot.lanzaboote.enable` is the modern path on NixOS; the
  # `or false` keeps the predicate evaluable on hosts that don't
  # import lanzaboote at all.
  lanzabooteEnabled = config.boot.lanzaboote.enable or false;
  # sd-stub with shim is the alternative path. We can't detect a
  # shim wrapper purely from config, but we can require lanzaboote
  # specifically for now and broaden if/when other declarative
  # approaches show up.
  declaredSecureBootEnabler = lanzabooteEnabled;

  probeScript = mkProbe {
    name = "secure-boot";
    runtimeInputs = with pkgs; [systemd];
    script = ''
      efi_supported="false"
      if [ -d /sys/firmware/efi ]; then
        efi_supported="true"
      fi

      secure_boot_active="false"
      if [ "$efi_supported" = "true" ]; then
        if bootctl status 2>/dev/null | grep -q "Secure Boot: enabled"; then
          secure_boot_active="true"
        fi
      fi

      # Firmware-side cross-check. The SecureBoot efivar at the
      # EFI_GLOBAL_VARIABLE GUID lays out as 4 attribute bytes
      # (uint32 LE) then a single value byte (0x01 enabled, 0x00
      # disabled). Reading the variable directly avoids depending
      # on the wording of `bootctl status` and surfaces a
      # divergence when the two sources disagree.
      firmware_secure_boot_active="unknown"
      sb_var="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
      if [ "$efi_supported" = "true" ] && [ -r "$sb_var" ]; then
        sb_byte=$(od -An -tu1 -j 4 -N 1 "$sb_var" 2>/dev/null | tr -d ' ' || true)
        if [ "$sb_byte" = "1" ]; then
          firmware_secure_boot_active="true"
        elif [ "$sb_byte" = "0" ]; then
          firmware_secure_boot_active="false"
        fi
      fi

      boot_loader="unknown"
      if command -v bootctl >/dev/null 2>&1; then
        boot_loader=$(bootctl status 2>/dev/null | head -1 || true)
        boot_loader="''${boot_loader:-unknown}"
      fi

      signed_entries_exist="false"
      if ls /boot/EFI/Linux/*.efi >/dev/null 2>&1; then
        signed_entries_exist="true"
      fi

      # The control reports compliance only when secure boot is
      # actually active AND the system has signed boot entries
      # backing it. Historically this short-circuited to true when
      # `requireSecureBoot=false` - that turned the control into a
      # no-op (issue #10), reporting hosts as compliant on a control
      # named "secureBoot" while secure boot was demonstrably off.
      # Operators who consciously waive secure boot should disable
      # the control entirely (`compliance.controls.secureBoot.enable
      # = false`) rather than have the probe lie.
      if [ "$secure_boot_active" = "true" ] && [ "$signed_entries_exist" = "true" ]; then
        compliant=true
      else
        compliant=false
      fi

      jq -n \
        --argjson compliant "$compliant" \
        --argjson efi_supported "$efi_supported" \
        --argjson secure_boot_active "$secure_boot_active" \
        --arg firmware_secure_boot_active "$firmware_secure_boot_active" \
        --arg boot_loader "$boot_loader" \
        --argjson signed_entries_exist "$signed_entries_exist" \
        '{
          compliant: $compliant,
          efi_supported: $efi_supported,
          secure_boot_active: $secure_boot_active,
          firmware_secure_boot_active: $firmware_secure_boot_active,
          boot_loader: $boot_loader,
          signed_entries_exist: $signed_entries_exist
        }'
    '';
  };
in {
  imports = [../evidence/options.nix ../governance/options.nix];

  options.compliance.controls.secureBoot = {
    enable = lib.mkEnableOption "secure boot compliance control (CRA Art. 10)";

    enforce = lib.mkOption {
      type = lib.types.bool;
      default = gov.enforceMode == "enforce";
      description = "Apply NixOS configuration. When false, only probes run.";
    };
  };

  config = lib.mkIf cfg.enable {
    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.secureBoot = {
      control = "secure-boot";
      type = "both";
      schema = schemaVersion;
      articles = {
        cra = ["Art. 10"];
        secnumcloud = ["boot"];
        nis2 = ["21(a)"];
        # ANSSI BP-028: framework preset enables this as "Additional
        # Controls" (docs/anssi-mapping.md) with no specific article;
        # empty list = control covers framework, no article.
        anssi-bp028 = [];
      };
      check = probeScript;
      staticEvidence = {
        # Predicate inspects whether the host has wired a
        # secure-boot enabling layer (lanzaboote today; broaden if
        # other paths land). The previous predicate
        # `systemdBootEnabled || grubEnabled` was true on every
        # NixOS install regardless of secure boot state - see
        # issue #10.
        passed = declaredSecureBootEnabler;
        evidence = {
          bootLoader = declaredBootLoader;
          configurationLimit = configurationLimit;
          lanzabooteEnabled = lanzabooteEnabled;
        };
      };
      probeDescriptor = {
        command = toString probeScript;
        args = [];
        timeoutSecs = 30;
        expect = {compliant = true;};
        schema = schemaVersion;
      };
    };
  };
}
