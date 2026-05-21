# controls/_baseline-hardening/rules.nix
#
# Baseline hardening rules implementing ANSSI R7-R14.
# Each rule = one ANSSI rule = one group of related sysctls/kernel params.
# Derived from cloud-gouv/securix:modules/anssi/{kernel-options,preboot}.nix (MIT). See NOTICES.
[
  # ── R7: IOMMU ──────────────────────────────────────
  {
    id = "BH-01";
    name = "enable-iommu";
    description = "Enable IOMMU to isolate DMA-capable devices (ANSSI R7)";
    severity = "strict";
    tags = ["kernel" "boot" "iommu"];
    hostTypes = [];
    architectures = ["x86_64"];
    articles = {
      anssi = ["R7"];
      nis2 = ["21(a)"];
    };
    config = {lib, ...}: {
      # `iommu=force` alone is insufficient - the kernel needs the
      # per-arch toggle to actually register IOMMU domains in
      # /sys/class/iommu/. Caught on lab (Intel M70q, VT-d
      # supported, DMAR detected by ACPI, `iommu=force` set, but
      # /sys/class/iommu/ was empty because intel_iommu=on wasn't
      # passed). `intel_iommu=on` is ignored on AMD CPUs and
      # vice-versa, so setting both is harmless and keeps the rule
      # arch-agnostic without threading gov.architecture through.
      boot.kernelParams = ["iommu=force" "intel_iommu=on" "amd_iommu=on"];
    };
    check = {mkProbe, ...}:
      mkProbe {
        name = "enable-iommu";
        script = ''
          iommu_dir="/sys/class/iommu"
          hardware_active=false
          if [ -d "$iommu_dir" ] && [ "$(ls -A $iommu_dir 2>/dev/null)" ]; then
            hardware_active=true
          fi

          cmdline=$(cat /proc/cmdline 2>/dev/null || echo "")
          param_present=false
          if echo "$cmdline" | grep -qE 'iommu=(force|pt|on)|amd_iommu=on|intel_iommu=on'; then
            param_present=true
          fi

          if [ "$hardware_active" = "true" ] && [ "$param_present" = "true" ]; then
            compliant=true
          else
            compliant=false
          fi

          jq -n \
            --argjson hardware_active "$hardware_active" \
            --argjson param_present "$param_present" \
            --argjson compliant "$compliant" \
            '{compliant: $compliant, hardware_active: $hardware_active, param_present: $param_present}'
        '';
      };
  }

  # ── R8: Memory boot options ────────────────────────
  {
    id = "BH-02";
    name = "memory-boot-hardening";
    description = "Kernel boot parameters for memory safety - L1TF, Meltdown, Spectre, MDS, slab hardening (ANSSI R8)";
    severity = "standard";
    tags = ["kernel" "boot" "memory"];
    hostTypes = [];
    architectures = ["x86_64"];
    articles = {
      anssi = ["R8"];
      nis2 = ["21(a)"];
    };
    config = {lib, ...}: {
      boot.kernelParams = [
        "l1tf=full,force"
        "page_poison=on"
        "pti=on"
        "slab_nomerge=yes"
        "slub_debug=FZP"
        "spec_store_bypass_disable=seccomp"
        "spectre_v2=on"
        "mds=full,nosmt"
        "mce=0"
        "page_alloc.shuffle=1"
        "rng_core.default_quality=500"
      ];
    };
    check = {mkProbe, ...}:
      mkProbe {
        name = "memory-boot-hardening";
        script = ''
          actual=$(cat /proc/cmdline 2>/dev/null || echo "")
          expected_params="l1tf=full,force page_poison=on pti=on slab_nomerge=yes slub_debug=FZP spec_store_bypass_disable=seccomp spectre_v2=on mds=full,nosmt mce=0 page_alloc.shuffle=1 rng_core.default_quality=500"
          missing=0
          total=0
          for param in $expected_params; do
            total=$((total + 1))
            if ! echo "$actual" | grep -q "$param"; then
              missing=$((missing + 1))
            fi
          done
          passed=$((total - missing))
          if [ "$missing" -eq 0 ]; then compliant=true; else compliant=false; fi
          jq -n --argjson compliant "$compliant" --argjson passed "$passed" --argjson total "$total" \
            '{compliant: $compliant, params_present: $passed, params_expected: $total}'
        '';
      };
  }

  # ── R9: Kernel sysctls ─────────────────────────────
  {
    id = "BH-03";
    name = "kernel-sysctl-hardening";
    description = "Kernel sysctl hardening - dmesg_restrict, kptr_restrict, ASLR, SysRq, BPF, panic_on_oops (ANSSI R9)";
    severity = "standard";
    tags = ["kernel" "sysctl"];
    hostTypes = [];
    articles = {
      anssi = ["R9"];
      nis2 = ["21(a)"];
      iso27001 = ["A.8.9"];
    };
    config = {lib, ...}: {
      boot.kernel.sysctl = {
        "kernel.dmesg_restrict" = lib.mkDefault 1;
        "kernel.kptr_restrict" = lib.mkForce 2;
        "kernel.perf_cpu_time_max_percent" = lib.mkDefault 1;
        "kernel.perf_event_max_sample_rate" = lib.mkDefault 1;
        "kernel.perf_event_paranoid" = lib.mkDefault 2;
        "kernel.randomize_va_space" = lib.mkDefault 2;
        "kernel.sysrq" = lib.mkDefault 0;
        "kernel.unprivileged_bpf_disabled" = lib.mkDefault 1;
        "kernel.panic_on_oops" = lib.mkDefault 1;
      };
    };
    check = {mkProbe, ...}:
      mkProbe {
        name = "kernel-sysctl-hardening";
        script = ''
          read_sysctl() { cat "/proc/sys/$1" 2>/dev/null || echo "unknown"; }
          dmesg=$(read_sysctl kernel/dmesg_restrict)
          kptr=$(read_sysctl kernel/kptr_restrict)
          aslr=$(read_sysctl kernel/randomize_va_space)
          sysrq=$(read_sysctl kernel/sysrq)
          bpf=$(read_sysctl kernel/unprivileged_bpf_disabled)

          perf_cpu=$(read_sysctl kernel/perf_cpu_time_max_percent)
          perf_rate=$(read_sysctl kernel/perf_event_max_sample_rate)
          perf_paranoid=$(read_sysctl kernel/perf_event_paranoid)
          panic=$(read_sysctl kernel/panic_on_oops)

          passed=0; total=9
          # Use -ge for security values: stricter than required is compliant.
          [ "$dmesg" -ge 1 ] 2>/dev/null && passed=$((passed + 1))
          [ "$kptr" -ge 2 ] 2>/dev/null && passed=$((passed + 1))
          [ "$aslr" -ge 2 ] 2>/dev/null && passed=$((passed + 1))
          [ "$sysrq" = "0" ] && passed=$((passed + 1))
          [ "$bpf" -ge 1 ] 2>/dev/null && passed=$((passed + 1))
          [ "$perf_cpu" -le 1 ] 2>/dev/null && passed=$((passed + 1))
          [ "$perf_rate" -le 1 ] 2>/dev/null && passed=$((passed + 1))
          [ "$perf_paranoid" -ge 2 ] 2>/dev/null && passed=$((passed + 1))
          [ "$panic" -ge 1 ] 2>/dev/null && passed=$((passed + 1))

          if [ "$passed" -eq "$total" ]; then compliant=true; else compliant=false; fi
          jq -n --argjson compliant "$compliant" --argjson passed "$passed" --argjson total "$total" \
            '{compliant: $compliant, checks_passed: $passed, checks_total: $total}'
        '';
      };
  }

  # ── R10: Disable kernel module loading ─────────────
  {
    id = "BH-04";
    name = "disable-kernel-module-loading";
    description = "Disable runtime loading of kernel modules (ANSSI R10)";
    severity = "paranoid";
    tags = ["kernel" "sysctl" "disable-kernel-module-loading"];
    hostTypes = [];
    articles = {
      anssi = ["R10"];
      nis2 = ["21(a)"];
    };
    config = {lib, ...}: {
      boot.kernel.sysctl."kernel.modules_disabled" = lib.mkDefault 1;
    };
    check = {mkProbe, ...}:
      mkProbe {
        name = "disable-kernel-module-loading";
        script = ''
          val=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo "0")
          if [ "$val" = "1" ]; then compliant=true; else compliant=false; fi
          jq -n --argjson compliant "$compliant" '{compliant: $compliant}'
        '';
      };
  }

  # ── R11: Yama LSM ──────────────────────────────────
  {
    id = "BH-05";
    name = "yama-ptrace-scope";
    description = "Enable Yama LSM and restrict ptrace scope (ANSSI R11)";
    severity = "standard";
    tags = ["kernel" "sysctl" "yama"];
    hostTypes = [];
    articles = {
      anssi = ["R11"];
      nis2 = ["21(a)"];
    };
    config = {lib, ...}: {
      boot.kernel.sysctl."kernel.yama.ptrace_scope" = lib.mkDefault 1;
    };
    check = {mkProbe, ...}:
      mkProbe {
        name = "yama-ptrace-scope";
        script = ''
          val=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "unknown")
          if [ "$val" -ge 1 ] 2>/dev/null; then compliant=true; else compliant=false; fi
          jq -n --argjson compliant "$compliant" --arg value "$val" '{compliant: $compliant, ptrace_scope: $value}'
        '';
      };
  }

  # ── R12: IPv4 network hardening ─────────────────────
  {
    id = "BH-06";
    name = "ipv4-network-hardening";
    description = "IPv4 sysctl hardening - BPF JIT, forwarding, ICMP redirects, ARP filtering, rp_filter, SYN cookies (ANSSI R12)";
    severity = "standard";
    tags = ["network" "sysctl" "ipv4"];
    hostTypes = [];
    articles = {
      anssi = ["R12"];
      nis2 = ["21(a)"];
    };
    config = {lib, ...}: {
      boot.kernel.sysctl = {
        "net.core.bpf_jit_harden" = lib.mkDefault 2;
        "net.ipv4.ip_forward" = lib.mkDefault 0;
        "net.ipv4.conf.all.accept_local" = lib.mkDefault 0;
        "net.ipv4.conf.all.accept_redirects" = lib.mkDefault 0;
        "net.ipv4.conf.default.accept_redirects" = lib.mkDefault 0;
        "net.ipv4.conf.all.secure_redirects" = lib.mkDefault 0;
        "net.ipv4.conf.default.secure_redirects" = lib.mkDefault 0;
        "net.ipv4.conf.all.shared_media" = lib.mkDefault 0;
        "net.ipv4.conf.default.shared_media" = lib.mkDefault 0;
        "net.ipv4.conf.all.arp_filter" = lib.mkDefault 1;
        "net.ipv4.conf.all.arp_ignore" = lib.mkDefault 2;
        "net.ipv4.conf.all.route_localnet" = lib.mkDefault 0;
        "net.ipv4.conf.all.drop_gratuitous_arp" = lib.mkDefault 1;
        "net.ipv4.conf.default.rp_filter" = lib.mkDefault 1;
        "net.ipv4.conf.all.rp_filter" = lib.mkDefault 1;
        "net.ipv4.conf.default.send_redirects" = lib.mkDefault 0;
        "net.ipv4.conf.all.send_redirects" = lib.mkDefault 0;
        "net.ipv4.icmp_ignore_bogus_error_responses" = lib.mkDefault 1;
        "net.ipv4.ip_local_port_range" = lib.mkDefault "32768 65535";
        "net.ipv4.tcp_rfc1337" = lib.mkDefault 1;
        "net.ipv4.tcp_syncookies" = lib.mkDefault 1;
        "net.ipv4.conf.all.log_martians" = lib.mkDefault 1;
        "net.ipv4.conf.default.log_martians" = lib.mkDefault 1;
      };
    };
    check = {mkProbe, ...}:
      mkProbe {
        name = "ipv4-network-hardening";
        script = ''
          read_sysctl() { cat "/proc/sys/$1" 2>/dev/null || echo "unknown"; }
          passed=0; total=0
          check_sysctl() {
            total=$((total + 1))
            local key="$1" expected="$2"
            local actual
            actual=$(read_sysctl "$key")
            if [ "$actual" = "$expected" ]; then
              passed=$((passed + 1))
            fi
          }

          check_sysctl net/core/bpf_jit_harden 2
          check_sysctl net/ipv4/ip_forward 0
          check_sysctl net/ipv4/conf/all/accept_local 0
          check_sysctl net/ipv4/conf/default/accept_redirects 0
          check_sysctl net/ipv4/conf/default/secure_redirects 0
          check_sysctl net/ipv4/conf/default/shared_media 0
          check_sysctl net/ipv4/conf/all/arp_filter 1
          check_sysctl net/ipv4/conf/all/arp_ignore 2
          check_sysctl net/ipv4/conf/all/route_localnet 0
          check_sysctl net/ipv4/conf/all/drop_gratuitous_arp 1
          check_sysctl net/ipv4/conf/default/rp_filter 1
          check_sysctl net/ipv4/conf/all/rp_filter 1
          check_sysctl net/ipv4/conf/default/send_redirects 0
          check_sysctl net/ipv4/conf/all/send_redirects 0
          check_sysctl net/ipv4/icmp_ignore_bogus_error_responses 1
          check_sysctl net/ipv4/tcp_rfc1337 1
          check_sysctl net/ipv4/tcp_syncookies 1
          check_sysctl net/ipv4/conf/all/log_martians 1
          check_sysctl net/ipv4/conf/default/log_martians 1

          if [ "$passed" -eq "$total" ]; then compliant=true; else compliant=false; fi
          jq -n --argjson compliant "$compliant" --argjson passed "$passed" --argjson total "$total" \
            '{compliant: $compliant, checks_passed: $passed, checks_total: $total}'
        '';
      };
  }

  # ── R13: Disable IPv6 ──────────────────────────────
  {
    id = "BH-07";
    name = "disable-ipv6";
    description = "Disable IPv6 on all interfaces (ANSSI R13)";
    severity = "strict";
    tags = ["network" "sysctl" "no-ipv6"];
    hostTypes = [];
    articles = {
      anssi = ["R13"];
      nis2 = ["21(a)"];
    };
    config = {lib, ...}: {
      boot.kernel.sysctl = {
        "net.ipv6.conf.default.disable_ipv6" = lib.mkForce 1;
        "net.ipv6.conf.all.disable_ipv6" = lib.mkForce 1;
      };
    };
    check = {mkProbe, ...}:
      mkProbe {
        name = "disable-ipv6";
        script = ''
          all=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "0")
          default=$(cat /proc/sys/net/ipv6/conf/default/disable_ipv6 2>/dev/null || echo "0")
          if [ "$all" = "1" ] && [ "$default" = "1" ]; then compliant=true; else compliant=false; fi
          jq -n --argjson compliant "$compliant" '{compliant: $compliant}'
        '';
      };
  }

  # ── R14: Filesystem protection ──────────────────────
  {
    id = "BH-08";
    name = "filesystem-sysctl-hardening";
    description = "Filesystem sysctl hardening - suid_dumpable, protected FIFOs/symlinks/hardlinks (ANSSI R14)";
    severity = "standard";
    tags = ["kernel" "sysctl" "filesystem"];
    hostTypes = [];
    articles = {
      anssi = ["R14"];
      nis2 = ["21(a)"];
    };
    config = {lib, ...}: {
      boot.kernel.sysctl = {
        "fs.suid_dumpable" = lib.mkDefault 0;
        "fs.protected_fifos" = lib.mkDefault 2;
        "fs.protected_regular" = lib.mkDefault 2;
        "fs.protected_symlinks" = lib.mkDefault 1;
        "fs.protected_hardlinks" = lib.mkDefault 1;
      };
    };
    check = {mkProbe, ...}:
      mkProbe {
        name = "filesystem-sysctl-hardening";
        script = ''
          read_sysctl() { cat "/proc/sys/$1" 2>/dev/null || echo "unknown"; }
          passed=0; total=4
          [ "$(read_sysctl fs/suid_dumpable)" = "0" ] && passed=$((passed + 1))
          [ "$(read_sysctl fs/protected_fifos)" = "2" ] && passed=$((passed + 1))
          [ "$(read_sysctl fs/protected_symlinks)" = "1" ] && passed=$((passed + 1))
          [ "$(read_sysctl fs/protected_hardlinks)" = "1" ] && passed=$((passed + 1))

          if [ "$passed" -eq "$total" ]; then compliant=true; else compliant=false; fi
          jq -n --argjson compliant "$compliant" --argjson passed "$passed" --argjson total "$total" \
            '{compliant: $compliant, checks_passed: $passed, checks_total: $total}'
        '';
      };
  }

  # ── Module blocklist ────────────────────────────────
  {
    id = "BH-09";
    name = "kernel-module-blocklist";
    description = "Blacklist dangerous kernel modules - USB storage, FireWire, Thunderbolt";
    severity = "strict";
    tags = ["kernel" "modules"];
    hostTypes = ["server" "appliance"];
    articles = {
      nis2 = ["21(a)" "21(g)"];
      iso27001 = ["A.8.9"];
    };
    config = {lib, ...}: {
      boot.blacklistedKernelModules = [
        "usb-storage"
        "firewire-core"
        "thunderbolt"
      ];
    };
    check = {mkProbe, ...}:
      mkProbe {
        name = "kernel-module-blocklist";
        script = ''
          blocked=0; total=3
          for mod in usb-storage firewire-core thunderbolt; do
            if ! lsmod 2>/dev/null | grep -q "^$mod "; then
              blocked=$((blocked + 1))
            fi
          done
          if [ "$blocked" -eq "$total" ]; then compliant=true; else compliant=false; fi
          jq -n --argjson compliant "$compliant" --argjson blocked "$blocked" --argjson total "$total" \
            '{compliant: $compliant, modules_blocked: $blocked, modules_expected: $total}'
        '';
      };
  }

  # ── IPv6 redirect hardening ─────────────────────────
  {
    id = "BH-10";
    name = "ipv6-redirect-hardening";
    description = "Disable IPv6 ICMP redirects (even when IPv6 is kept enabled)";
    severity = "standard";
    tags = ["network" "sysctl" "ipv6"];
    hostTypes = [];
    articles = {
      nis2 = ["21(a)"];
      iso27001 = ["A.8.9"];
    };
    config = {lib, ...}: {
      boot.kernel.sysctl = {
        "net.ipv6.conf.all.accept_redirects" = lib.mkDefault 0;
        "net.ipv6.conf.default.accept_redirects" = lib.mkDefault 0;
      };
    };
    check = {mkProbe, ...}:
      mkProbe {
        name = "ipv6-redirect-hardening";
        script = ''
          all=$(cat /proc/sys/net/ipv6/conf/all/accept_redirects 2>/dev/null || echo "unknown")
          default=$(cat /proc/sys/net/ipv6/conf/default/accept_redirects 2>/dev/null || echo "unknown")
          if [ "$all" = "0" ] && [ "$default" = "0" ]; then compliant=true; else compliant=false; fi
          jq -n --argjson compliant "$compliant" '{compliant: $compliant}'
        '';
      };
  }
]
