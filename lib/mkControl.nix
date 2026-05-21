# lib/mkControl.nix
#
# mkControl: generates a NixOS module from a control definition with rules.
# Architecture derived from cloud-gouv/securix:modules/anssi/generator.nix (MIT). See NOTICES.
#
# Usage:
#   import ../lib/mkControl.nix {
#     controlId = "baselineHardening";
#     controlName = "baseline-hardening";
#     controlDescription = "Baseline OS hardening";
#     articles = { nis2 = ["21(a)"]; };
#     rules = import ./rules.nix;
#   }
#
# `controlId` is the NixOS option path (camelCase, required). `controlName`
# is the kebab-case display name surfaced in evidence.json and the
# compliance-check table; defaults to `controlId` for backward compat,
# but multi-word controls should pass it explicitly to match the
# kebab-case convention single-file controls already use.
{
  controlId,
  controlName ? controlId,
  controlDescription,
  articles ? {},
  extraOptions ? {},
  rules,
}: {
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.${controlId};
  gov = config.compliance.governance;
  mkProbe = import ./mkProbe.nix {inherit pkgs lib;};

  levelMapping = {
    "minimal" = 0;
    "standard" = 1;
    "strict" = 2;
    "paranoid" = 3;
  };

  # Determine if a rule should be enabled based on governance policy
  ruleEnabled = rule:
    cfg.enable
    && levelMapping.${gov.level} >= levelMapping.${rule.severity}
    && (rule.hostTypes == [] || lib.elem gov.hostType rule.hostTypes)
    && ((rule.architectures or []) == [] || lib.elem gov.architecture (rule.architectures or []))
    && lib.all (t: !(lib.elem t gov.excludes)) (rule.tags or [])
    && !(gov.exceptions ? ${rule.id});

  # Determine why a rule is disabled (for compliance report)
  exclusionReason = rule:
    if !(cfg.enable)
    then {
      reason = "control ${controlId} is disabled";
      via = "control";
    }
    else if levelMapping.${gov.level} < levelMapping.${rule.severity}
    then {
      reason = "severity ${rule.severity} exceeds governance level ${gov.level}";
      via = "level";
      requiredLevel = rule.severity;
    }
    else if rule.hostTypes != [] && !(lib.elem gov.hostType rule.hostTypes)
    then {
      reason = "not applicable to host type ${gov.hostType}";
      via = "hostType";
      requiredHostTypes = rule.hostTypes;
    }
    else if (rule.architectures or []) != [] && !(lib.elem gov.architecture (rule.architectures or []))
    then {
      reason = "not applicable to architecture ${gov.architecture}";
      via = "architecture";
      requiredArchitectures = rule.architectures or [];
    }
    else if lib.any (t: lib.elem t gov.excludes) (rule.tags or [])
    then {
      reason = "excluded by tag ${lib.concatStringsSep ", " (lib.filter (t: lib.elem t gov.excludes) (rule.tags or []))}";
      via = "tag";
    }
    else if gov.exceptions ? ${rule.id}
    then {
      reason = "excluded by exception: ${gov.exceptions.${rule.id}.rationale}";
      via = "exception";
      rationale = gov.exceptions.${rule.id}.rationale;
    }
    else {
      reason = "explicitly disabled by user";
      via = "override";
    };

  # Generate options for each rule
  ruleOptions = lib.listToAttrs (map (
      rule:
        lib.nameValuePair rule.id ({
            enable = lib.mkOption {
              type = lib.types.bool;
              default = ruleEnabled rule;
              description = ''
                Enable rule ${rule.id} (${rule.name}).
                ${rule.description}
                Severity: ${rule.severity}.
              '';
            };
          }
          // lib.optionalAttrs (rule ? implementations) {
            implementation = lib.mkOption {
              type = lib.types.enum (lib.attrNames rule.implementations);
              default = lib.head (lib.attrNames rule.implementations);
              description = ''
                Implementation variant for rule ${rule.id}.
                Available: ${lib.concatStringsSep ", " (lib.attrNames rule.implementations)}.
              '';
            };
          })
    )
    rules);

  # Build enforcement config from enabled rules
  enabledRuleConfigs = lib.mkMerge (map (
      rule:
        lib.mkIf (cfg.rules.${rule.id}.enable && cfg.enforce) (
          if rule ? implementations
          then rule.implementations.${cfg.rules.${rule.id}.implementation}.config {inherit lib pkgs config;}
          else rule.config {inherit lib pkgs config;}
        )
    )
    rules);

  # Aggregate probe - runs all rule probes and merges results
  aggregateProbe = mkProbe {
    name = controlId;
    script = let
      ruleProbes = lib.filter (rule: cfg.rules.${rule.id}.enable) rules;
    in ''
      results="{}"
      overall_compliant=true
      ${lib.concatMapStringsSep "\n" (rule: let
          probe =
            if rule ? implementations
            then (rule.implementations.${cfg.rules.${rule.id}.implementation}.check or rule.check) {inherit pkgs lib mkProbe;}
            else rule.check {inherit pkgs lib mkProbe;};
        in ''
          # Rule ${rule.id}: ${rule.name}
          if rule_output=$("${probe}" 2>/dev/null); then
            results=$(echo "$results" | jq --arg id "${rule.id}" --argjson out "$rule_output" '. + {($id): $out}')
            rule_compliant=$(echo "$rule_output" | jq -r 'if has("compliant") then .compliant else true end')
            if [ "$rule_compliant" = "false" ]; then
              overall_compliant=false
            fi
          else
            results=$(echo "$results" | jq --arg id "${rule.id}" '. + {($id): {"error": "probe failed"}}')
            overall_compliant=false
          fi
        '')
        ruleProbes}

      jq -n \
        --argjson rules "$results" \
        --argjson compliant "$overall_compliant" \
        '{ rules: $rules, compliant: $compliant }'
    '';
  };

  # Build exclusions map for the report
  exclusions = lib.listToAttrs (
    map (rule: lib.nameValuePair rule.id (exclusionReason rule))
    (lib.filter (rule: !(cfg.rules.${rule.id}.enable)) rules)
  );

  # Aggregate per-rule article maps into the control-level `articles`.
  # Rules are the source of truth for ANSSI BP-028 (fine-grained:
  # R7..R14 each map to a single rule inside _baseline-hardening,
  # R33 maps to a single rule inside _audit-logging), so the control-
  # level `articles` map must mirror the union of its rules'
  # framework→articles entries — otherwise the agent's whole-framework
  # probe (which keys on the control-level `frameworkArticles`) finds
  # no controls covering ANSSI and the gate fails (incident at
  # 18:03:22 lab activation, sustained-failure rollback).
  #
  # Rule articles keys are short names (`anssi`, `nis2`, …); the
  # wire/probe lookup uses the framework's full name (`anssi-bp028`).
  # `frameworkKeyMap` normalises the asymmetry at aggregation time so
  # the rule-authoring shorthand stays concise while the emitted
  # control-level map matches the agent's lookup key. Other frameworks
  # are 1:1 between short name and wire name and pass through unchanged.
  #
  # The control's static `articles` (the `mkControl` argument) is the
  # base; rule-aggregated articles add to it via per-framework union.
  # An explicit empty-list entry in the static `articles` (e.g.
  # `anssi-bp028 = []` on a single-script control) is preserved — the
  # agent treats it as "control covers framework, no specific
  # article" and emits one sub-result without an article.
  frameworkKeyMap = {
    anssi = "anssi-bp028";
  };
  normaliseFrameworkKey = k: frameworkKeyMap.${k} or k;
  aggregatedRuleArticles =
    lib.foldl' (
      acc: rule:
        lib.foldl' (
          acc2: shortKey: let
            wireKey = normaliseFrameworkKey shortKey;
            existing = acc2.${wireKey} or [];
            incoming = rule.articles.${shortKey};
          in
            acc2 // {${wireKey} = lib.unique (existing ++ incoming);}
        )
        acc
        (lib.attrNames (rule.articles or {}))
    ) {}
    rules;
  mergedArticles =
    lib.foldl' (
      acc: k: let
        existing = acc.${k} or [];
        incoming = aggregatedRuleArticles.${k};
      in
        acc // {${k} = lib.unique (existing ++ incoming);}
    )
    articles (lib.attrNames aggregatedRuleArticles);
in {
  imports = [
    ../governance/options.nix
    ../evidence/options.nix
  ];

  options.compliance.controls.${controlId} =
    {
      enable = lib.mkEnableOption "${controlDescription}";

      enforce = lib.mkOption {
        type = lib.types.bool;
        default = gov.enforceMode == "enforce";
        description = ''
          Whether this control applies NixOS configuration (enforcement).
          When false, only evidence probes run (report-only mode).
          Defaults to the governance-level enforceMode.
        '';
      };

      rules = ruleOptions;

      _meta = lib.mkOption {
        type = lib.types.attrs;
        default = {
          inherit controlId controlName controlDescription;
          articles = mergedArticles;
          inherit exclusions;
          ruleCount = builtins.length rules;
          enabledRuleCount = builtins.length (lib.filter (rule: cfg.rules.${rule.id}.enable) rules);
        };
        readOnly = true;
        internal = true;
        description = "Internal metadata for compliance report generation";
      };
    }
    // extraOptions;

  config = lib.mkIf cfg.enable (lib.mkMerge [
    # Enforcement - only when enforce = true
    enabledRuleConfigs

    # Evidence - always when control is enabled
    {
      compliance.evidence.collector.enable = lib.mkDefault true;

      compliance.evidence.probes.${controlId} = {
        control = controlName;
        articles = mergedArticles;
        check = aggregateProbe;
      };
    }
  ]);
}
