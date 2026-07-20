# Compatibility

Bulwark Free is built for Java 8 bytecode and is tested with modern Java runtimes.

Supported target:

- Minecraft 1.13 through current 1.21.x releases;
- Spigot API style servers;
- Paper, Purpur, Pufferfish, Leaf and Folia;
- common Bukkit hybrid servers such as Arclight, Mohist and Magma.

Best-effort detection:

- Fabric;
- Quilt;
- Forge;
- NeoForge;
- hybrid Bukkit plus modded runtimes.

Loader detection is intentionally conservative. A `mods/` folder alone is not treated as proof of a modded runtime; Bulwark looks for loader evidence to avoid noisy reports on servers that only have leftover folders.

## Hosting environments

Bulwark runs the same way no matter where your server lives. The audit reads files in the server folder, so it does not need root, SSH or any host-level access to grade your posture.

- Self-managed boxes: VPS, dedicated servers and bare metal.
- Game-server panels: Pterodactyl, Multicraft and the game hosts built on them.
- Shared game hosting and any other Minecraft host.

Identity is never tied to hardware, so nothing breaks when a panel restarts your container and the machine id changes.

The optional host checks (file permissions, the OS user the server runs as, JVM heap vs. RAM) need filesystem access to the host, so they do their full work on boxes you manage yourself. On panels or shared hosting, where you do not see the host, Bulwark detects the managed environment, adjusts what it can verify and skips the rest instead of reporting false problems.

Legacy 1.8 through 1.12 servers may need a separate build without `api-version`. Test that build on a staging server before using it in production.
