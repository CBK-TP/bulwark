# Bulwark

Bulwark is a local security audit for Minecraft Java servers. Run one command and it
checks the server files an admin would normally inspect by hand: `server.properties`,
Paper/Spigot/Bukkit config, operators, plugin jars, datapacks, command surface, runtime
details and basic host file permissions.

Free is designed as a scanner, not a fixer. Its public command surface does not edit
`server.properties`, disable plugins, delete jars or change third-party plugin data. It
writes only inside `plugins/Bulwark/` for its own config, consent marker, reports, badge,
language overrides and plugin trust baseline.

## Requirements

- Spigot, Paper, Purpur, Pufferfish, Leaf and Folia
- Bukkit hybrid servers such as Arclight, Mohist and Magma
- Minecraft 1.13 through current 1.21.x releases
- Java 8 through Java 21
- English, Spanish, German and French built in

There are no bundled runtime dependencies. The jar uses the Bukkit/Spigot API provided by
the server.

## What It Checks

- Authentication posture: offline mode, proxy context, whitelist, secure profile and OP count
- Exposed services: RCON, query, transfers, command blocks and command permissions
- Proxy safety: BungeeCord mode, Velocity forwarding and backend firewall posture
- Runtime: Java version, known Log4Shell-era server versions and JVM/host basics
- Loader context: Bukkit/Paper/Folia plus best-effort Fabric, Quilt, Forge and NeoForge evidence
- Plugins and artifacts: duplicate jars, misplaced jars, disabled jars, datapacks and loadable jars outside normal folders
- Command surface: public disclosure, namespace bypasses, shadowed aliases and risky plugin-manager commands
- Public survival hardening: Paper anti-xray, resource-pack hash and common protection gaps

Findings are mapped to the Cobayka Hardening Baseline, grouped by area and shown with a
letter grade. Performance and hardening notes are visible, but advisory findings do not
silently drag the security grade down.

## Commands

`/bulwark` also works as `/secaudit` or `/bw`.

| Command | Purpose |
| --- | --- |
| `/bulwark run` | Run the audit summary |
| `/bulwark full` | Show every finding |
| `/bulwark report` | Write `.txt` and Markdown reports under `plugins/Bulwark/` |
| `/bulwark badge` | Generate a local SVG badge |
| `/bulwark consent [on/off]` | Allow or revoke local file scanning |
| `/bulwark trust [status/baseline/accept/reset]` | Manage the local plugin hash baseline |
| `/bulwark inventory` | Show detected plugins, mods, datapacks and server artifacts |
| `/bulwark commands [summary/risky/duplicates/all]` | Inspect the registered command surface |
| `/bulwark posture` | Show detected server profile and loader evidence |
| `/bulwark artifact info <name>` | Inspect a detected artifact |
| `/bulwark artifact configs <name>` | List related config files |
| `/bulwark artifact check <name>` | Run optional external advisory checks if enabled |
| `/bulwark reload` | Reload Bulwark config |

Only `bulwark.admin` is required, and it defaults to server operators.

## Configuration

Use `plugins/Bulwark/config.yml`, then run `/bulwark reload`.

- Set `scan-consent: true`, or use `/bulwark consent`, before local file scanning.
- Use `ignore` to silence specific finding IDs.
- Use `severity-overrides` to adapt a finding to your server posture.
- Tune thresholds for operators, RCON password length and view/simulation distance.
- Set `advisory.enabled: true` only if you want opt-in checks against external advisory services.
- Set `language` to `en`, `es`, `de` or `fr`, or provide overrides in `plugins/Bulwark/lang/`.

Bulwark is guidance, not a guarantee. It helps find common risks and explain them clearly;
it does not replace a full review of your server, host and operational process.
