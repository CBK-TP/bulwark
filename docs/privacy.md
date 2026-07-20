# Privacy

Bulwark Free runs locally inside your Minecraft server.

## Local Reads

After consent, the scanner may read:

- Minecraft server config such as `server.properties`;
- Bukkit, Spigot and Paper config files;
- operator, whitelist and ban files;
- plugin metadata and plugin jar hashes;
- datapack and artifact metadata;
- command registrations exposed by the server;
- basic host file permissions and runtime information.

## Local Writes

Free writes only under `plugins/Bulwark/`:

- `config.yml`;
- `.consent`;
- audit reports;
- `badge.svg`;
- `trusted-plugins.tsv`;
- optional language overrides supplied by the admin.

Free does not edit `server.properties`, disable plugins, delete jars or change third-party plugin data through its public commands.

## Network

No external advisory lookup is performed unless the admin enables it and runs the relevant artifact check.

When advisory checks are enabled, Bulwark may send plugin or artifact names, versions and hashes to the configured public services. Do not enable this on servers where that metadata must stay private.

Bulwark does not auto-update its jar.
