# controls/_audit-logging/rules.nix
#
# Audit logging rules - journald persistence + auditd enforcement.
# AL-02 derived from cloud-gouv/securix:modules/auditd.nix (MIT). See NOTICES.
[
  # ── Journald persistence ───────────────────────────
  {
    id = "AL-01";
    name = "journald-persistence";
    description = "Persistent journal storage with compression and retention";
    severity = "minimal";
    tags = ["logging" "journald"];
    hostTypes = [];
    articles = {
      nis2 = ["21(b)" "21(f)"];
      iso27001 = ["A.8.15" "A.8.16"];
    };
    config = {
      lib,
      config,
      ...
    }: let
      retentionDays = config.compliance.controls.auditLogging.retentionDays or 365;
    in {
      services.journald.extraConfig = ''
        Storage=persistent
        MaxRetentionSec=${toString (retentionDays * 24)}h
        Compress=yes
      '';
    };
    check = {
      pkgs,
      mkProbe,
      ...
    }:
      mkProbe {
        name = "journald-persistence";
        runtimeInputs = [pkgs.systemd];
        script = ''
          if [ -d /var/log/journal ]; then
            journal_persistent=true
          else
            journal_persistent=false
          fi

          journal_disk_usage=$(journalctl --disk-usage 2>/dev/null \
            | grep -oP '[\d.]+[GMKT]' || true)
          journal_disk_usage="''${journal_disk_usage:-unknown}"

          jq -n \
            --argjson journal_persistent "$journal_persistent" \
            --arg journal_disk_usage "$journal_disk_usage" \
            --argjson compliant "$journal_persistent" \
            '{journal_persistent: $journal_persistent, journal_disk_usage: $journal_disk_usage, compliant: $compliant}'
        '';
      };
  }

  # ── Auditd (ANSSI R33) ───────────────
  {
    id = "AL-02";
    name = "auditd-enforcement";
    description = "Enable auditd with execve tracking and log rotation (ANSSI R33)";
    severity = "standard";
    tags = ["logging" "auditd" "anssi"];
    hostTypes = [];
    articles = {
      anssi = ["R33"];
      nis2 = ["21(b)" "21(f)"];
      iso27001 = ["A.8.15" "A.8.16"];
    };
    config = {
      lib,
      config,
      ...
    }: let
      adminEmail = config.compliance.controls.auditLogging.adminEmail or null;
    in {
      security.auditd.enable = true;
      security.audit = {
        enable = true;
        rules = [
          "-a exit,always -F arch=b64 -S execve"
        ];
      };
      environment.etc."audit/auditd.conf".text = lib.mkForce ''
        num_logs = 10
        max_log_file = 100
        max_log_file_action = rotate
        space_left = 10%
        space_left_action = ${
          if adminEmail != null
          then "email"
          else "syslog"
        }
        admin_space_left = 5%
        admin_space_left_action = ${
          if adminEmail != null
          then "email"
          else "suspend"
        }
        ${lib.optionalString (adminEmail != null) "action_mail_acct = ${adminEmail}"}
      '';
    };
    check = {
      pkgs,
      mkProbe,
      ...
    }:
      mkProbe {
        name = "auditd-enforcement";
        runtimeInputs = [pkgs.systemd pkgs.audit];
        script = ''
          auditd_active="false"
          if systemctl is-active auditd.service >/dev/null 2>&1; then
            auditd_active="true"
          fi

          audit_rules_count=0
          if command -v auditctl >/dev/null 2>&1; then
            audit_rules_count=$(auditctl -l 2>/dev/null | wc -l || echo "0")
          fi

          has_rotation="false"
          if [ -f /etc/audit/auditd.conf ]; then
            if grep -q "max_log_file_action.*=.*rotate" /etc/audit/auditd.conf 2>/dev/null; then
              has_rotation="true"
            fi
          fi

          if [ "$auditd_active" = "true" ] && [ "$audit_rules_count" -gt 0 ] 2>/dev/null; then
            compliant=true
          else
            compliant=false
          fi

          jq -n \
            --argjson auditd_active "$auditd_active" \
            --argjson audit_rules_count "$audit_rules_count" \
            --argjson has_log_rotation "$has_rotation" \
            --argjson compliant "$compliant" \
            '{auditd_active: $auditd_active, audit_rules_count: $audit_rules_count, has_log_rotation: $has_log_rotation, compliant: $compliant}'
        '';
      };
  }

  # ── Log forwarding ─────────────────────────────────
  {
    id = "AL-03";
    name = "log-forwarding";
    description = "Remote log forwarding for centralized audit trail";
    severity = "strict";
    tags = ["logging" "forwarding"];
    hostTypes = [];
    articles = {
      nis2 = ["21(b)"];
      iso27001 = ["A.8.15" "A.8.16"];
      dora = ["Art. 17"];
    };
    config = {lib, ...}: {
      # No enforcement - log forwarding is fleet-specific.
      # Users configure vector/promtail/rsyslog/syslog-ng at the fleet level.
      # The probe below detects whichever is running.
    };
    check = {mkProbe, ...}:
      mkProbe {
        name = "log-forwarding";
        script = ''
          # Check for common log forwarding services
          forwarding_active=false
          for svc in vector.service promtail.service rsyslog.service syslog-ng.service; do
            if systemctl is-active "$svc" >/dev/null 2>&1; then
              forwarding_active=true
              break
            fi
          done
          jq -n --argjson forwarding_active "$forwarding_active" --argjson compliant "$forwarding_active" \
            '{forwarding_active: $forwarding_active, compliant: $compliant}'
        '';
      };
  }
]
