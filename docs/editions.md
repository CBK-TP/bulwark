# Editions

## Free

Free is the open source scanner in this repository.

- Manual audits.
- Local reports.
- Badge generation.
- Plugin trust baseline.
- Inventory and command surface checks.
- Optional advisory checks.

Free is for understanding the current posture.

## Pro

Pro adds monitoring and workflow convenience:

- scheduled scans;
- grade history;
- digest of new, persistent and resolved findings;
- webhook reports;
- local web panel;
- staged config changes for Bulwark's own `config.yml`.

Pro does not disable plugins or edit third-party plugin data.

## Ultimate

Ultimate adds controlled response:

- licence-gated paid actions;
- drift watch;
- active guards;
- lockdown;
- reversible hardening for a small set of safe `server.properties` keys;
- hash-chained local security log;
- plugin audit views.

Active blocking is disabled by default. Console and RCON are not cancelled by command guards. Remediation creates a backup before writing and supports rollback.

The paid implementation is private. Public docs describe expected behavior so server owners can review the safety model before buying.
