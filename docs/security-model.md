# Security Model

Bulwark Free is a scanner.

It reports posture risks and explains fixes, but it does not apply fixes automatically. That split is deliberate: scanner output should be easy to inspect, safe to run and hard to mistake for an enforcement layer.

## Free Edition

- Manual scan and report.
- Consent-gated local file reads.
- No background guard.
- No automatic plugin or jar changes.
- No remote rule execution.
- No jar auto-update.
- Advisory lookups are opt-in.

## Paid Editions

Paid editions add continuous monitoring and response workflows. Their behavior is documented publicly, but their implementation is not part of this repository.

The important safety promises are:

- dangerous actions require explicit admin commands or panel sessions;
- active guards are alert-only by default;
- command blocking does not cancel console or RCON;
- hardening writes are narrow, backed up and reversible;
- licence failures must not be confused with server outages.

See `docs/editions.md` for the public contract.
