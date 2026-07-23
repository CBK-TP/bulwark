# Community Rules

The community rules engine is **active in the current Free release**. It evaluates a **bundled** ruleset that
ships inside the jar (`resources/rules/community-rules.yml`).

Two things are deliberately **not** enabled yet:

- **External rule files are not loaded.** The engine only reads the ruleset bundled in the jar. Dropping a
  YAML file into `plugins/Bulwark/rules/` does nothing today.
- **Rule pull requests are not open yet.** The current ruleset is curated in-house. We will open contributions
  once we can review them at the pace they deserve.

## Principles

- rules are data, not code;
- no scripts, no remote jars, no automatic downloads, no network access, no regular expressions;
- broken rules fail open and are reported as diagnostics, never as a server risk;
- rule findings start conservative to avoid noisy grades;
- every accepted rule needs evidence and a fixture.

## Guarantees

These are enforced in code, not just intended:

- **Community findings never change the A-F grade.** They are collected in a separate list that the scoring
  loop never walks, they use an area that is not part of the graded areas, and they are rendered in their own
  advisory section. A regression test asserts that a HIGH community finding leaves the score untouched.
- **An unparseable version is never treated as vulnerable.** If a version string cannot be parsed with
  confidence (`1.2.4-SNAPSHOT`, `1.20.1-R0.1`, `${project.version}`, empty, …) the comparison returns
  *unknown* and the rule does **not** match, unless the rule explicitly opts in with `versionUnknown: true`.
- **A rule that opts into unknown versions can only be LOW or INFO.** This is validated when the ruleset is
  loaded; a `versionUnknown` rule with a higher severity is rejected.
- **Everything is bounded.** Rule file ≤ 256 KB, scanned config file ≤ 128 KB, ≤ 64 rules, condition depth
  ≤ 6, strings ≤ 768 characters, ≤ 5 sources per rule.

## Rule format

```yaml
ruleset:
  id: bulwark-community
  version: 2026.07.23
  minEngine: 1

rules:
  - id: community.plugin.example-advisory-ghsa-xxxx
    severity: high            # critical | high | medium | low | info
    category: community-rules # optional
    title: "Short, factual headline"
    detail: "What was observed and why it matters."
    fix: "The concrete action an admin should take."
    sources:
      - "https://github.com/owner/repo/security/advisories/GHSA-xxxx"
    when:
      all:
        - plugin:
            names: ["ExamplePlugin", "ExamplePluginAlt"]
            version:
              any:
                - "<= 1.2.4"
                - ">= 2.0.0 <= 2.1.3"
        - yamlConfig:
            path: "plugins/ExamplePlugin/config.yml"
            key: "risky-feature"
            equals: "true"
```

### Conditions

Combinators: `all`, `any`, `not`.

| Matcher | Fields |
|---|---|
| `plugin` | `names` (list), `version`, `loader`, `pathScope` |
| `artifact` | same as `plugin`, plus `type` (`plugin` / `mod`) |
| `serverProperty` | `key` (required), `equals`, `present` |
| `yamlConfig` | `path` (required), `key` (required), `equals`, `present` |
| `server` | `platform`, `loader`, `version` |
| `protection` | `categoryMissing` |
| `posture` | `profile` |

### Version specs

Inside a `version:` block you can use `range`, `lt`, `lte`, `gt`, `gte`, `eq`, or `any:` with a list of range
expressions. A range expression is a space-separated conjunction, e.g. `">= 3.8.0 <= 3.8.3"`. Versions are
compared component by component as integers; a leading `v` is stripped; missing components count as `0`
(so `1.2` < `1.2.4`). `versionUnknown: true` makes the rule apply when the version cannot be parsed — and, as
above, restricts the rule to LOW or INFO.

## What makes a good rule

The engine already hardcodes a broad set of configuration checks. A community rule earns its place by covering
the **long tail those checks cannot express without a new release** — above all, advisories tied to a specific
plugin or mod version, backed by a citable source (CVE, GHSA, or a vendor advisory).

Severity should track **confidence**, not drama. Only a rule with an exact match shape, a credible source, a
clear version range and a fixture belongs at HIGH or CRITICAL. Anything softer belongs at LOW or INFO. In a
security plugin, a false positive costs more than a missed advisory.
