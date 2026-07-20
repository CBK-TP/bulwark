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

Legacy 1.8 through 1.12 servers may need a separate build without `api-version`. Test that build on a staging server before using it in production.
