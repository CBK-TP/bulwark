# Community Rules

This directory is reserved for the public ruleset and fixtures.

The engine is active in the current release, but it only evaluates the ruleset **bundled inside the jar**.
External rule files placed here (or in `plugins/Bulwark/rules/`) are **not loaded yet** — that stays off until
the fixture format and the false-positive review process are ready to take contributions.

Rules are declarative YAML. They never execute scripts, reach the network, or modify server files.
See `docs/rule-authoring.md` for the format and the guarantees.
