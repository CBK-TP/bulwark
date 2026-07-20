# Bulwark

Bulwark is an open source security audit plugin for Minecraft Java servers.

It is meant for server owners who want a clear answer to a simple question: "what looks risky on this server right now?" The plugin reads local server state, maps the findings to a letter grade, and gives practical fixes without changing your server for you.

Free is the public scanner. Paid editions add monitoring, history, alerts, panel workflows and controlled response, but their source code is not part of this repository.

## What Bulwark Free Does

- Audits common Minecraft server risks from one command.
- Runs anywhere your server does — VPS, dedicated, or a game-server panel like Pterodactyl or Multicraft. It reads files, so it needs no host access.
- Detects Bukkit/Paper/Folia context, common hybrid loaders and modded-server evidence.
- Checks access posture, proxy safety, RCON/query exposure, OPs, command surface, plugin jars, datapacks and basic host file permissions.
- Writes reports, Markdown output and a local badge under `plugins/Bulwark/`.
- Keeps external advisory checks disabled unless the admin opts in.
- Avoids automatic updates, remote code and background enforcement in the Free edition.

Free does not edit `server.properties`, disable plugins, delete jars or change third-party plugin data through its public commands.

## Build

Requirements:

- JDK 17 to build
- Maven 3.9+
- The built plugin targets Java 8 bytecode

```bash
mvn test package
```

The jar is written to:

```text
bulwark/target/Bulwark-1.0.0.jar
```

## Install

1. Drop the jar into `plugins/`.
2. Start the server once.
3. Run `/bulwark consent` or set `scan-consent: true` in `plugins/Bulwark/config.yml`.
4. Run `/bulwark full` or `/bulwark report`.

Command aliases: `/bulwark`, `/bw`, `/secaudit`.

## Repository Layout

```text
bulwark/             Free plugin source
docs/                Public user and maintainer docs
community-rules/     Public rules area, currently reserved for the rules engine
.github/             CI and issue templates
```

## Editions

This repository contains Bulwark Free only.

- Free: manual local scanner and reports.
- Pro: scheduled audits, history, digest, webhook and panel workflows.
- Ultimate: licence-gated operational response, drift, guards, lockdown and reversible hardening.

The paid editions are documented publicly so buyers can understand the safety model, but their implementation remains private.

## Licence

Bulwark Free is licensed under the Apache License 2.0. See `LICENSE`.

The Bulwark name, Cobayka name, Cobayka Hardening Baseline, CHB naming and Bulwark badge wording are covered by `TRADEMARK.md`.
