package es.cobayka.bulwark;

import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.util.LinkedHashSet;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.security.MessageDigest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Finds the server's working directory and reads its config files. Read-only - reading
 * the files directly (instead of version-specific API) is what keeps Bulwark working the
 * same across Spigot/Paper/Purpur/Folia and a wide range of Minecraft versions, and lets the
 * audit run safely off the main thread (for scheduled scans and the drift watch on Folia).
 *
 * This class is shared verbatim across the free, Pro and Ultimate builds - some methods are only
 * used by the paid tiers (uuidsIn / pluginJarHashes drive Ultimate's drift watch).
 */
final class ServerEnv {

    private final JavaPlugin plugin;
    private final File root;

    ServerEnv(JavaPlugin plugin) {
        this.plugin = plugin;
        // plugins/<this plugin>/ -> plugins/ -> server root
        File dataFolder = plugin.getDataFolder();
        File pluginsDir = dataFolder.getParentFile();
        File candidate = (pluginsDir != null && pluginsDir.getParentFile() != null)
                ? pluginsDir.getParentFile() : new File(".");
        // If the computed root doesn't look like a server root, fall back to the working directory.
        if (!new File(candidate, "server.properties").isFile() && new File("server.properties").isFile()) {
            candidate = new File(".").getAbsoluteFile();
        }
        this.root = candidate;
    }

    File pluginsDir() {
        return new File(root, "plugins");
    }

    /** The server's working directory. */
    File root() {
        return root;
    }

    /** A file relative to the server root. */
    File file(String name) {
        return new File(root, name);
    }

    /** A single server.properties value, trimmed, or "" if missing. */
    String prop(String key) {
        return serverProperties().getProperty(key, "").trim();
    }

    /** Number of server operators, read from ops.json. Returns -1 if it can't be read. */
    int operatorCount() {
        File f = new File(root, "ops.json");
        if (!f.isFile()) {
            return -1;
        }
        try {
            String text = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
            int count = 0;
            Matcher m = UUID_FIELD.matcher(text); // count actual "uuid": entries, not stray substrings
            while (m.find()) {
                count++;
            }
            return count;
        } catch (Exception ex) {
            return -1;
        }
    }

    /** Lower-cased names of every loaded plugin, for "is X installed?" checks. */
    Set<String> loadedPluginNames() {
        Set<String> out = new LinkedHashSet<>();
        try {
            for (Plugin p : plugin.getServer().getPluginManager().getPlugins()) {
                if (p != null && p.getName() != null) {
                    out.add(p.getName().toLowerCase(java.util.Locale.ROOT));
                }
            }
        } catch (Exception ignored) {
            // empty on failure
        }
        return out;
    }

    /**
     * The set of player UUIDs listed in a server JSON file (whitelist.json, banned-players.json...).
     * Parsed leniently so it doesn't depend on a JSON lib. Empty if missing/unreadable.
     */
    Set<String> uuidsIn(String fileName) {
        Set<String> out = new LinkedHashSet<>();
        File f = new File(root, fileName);
        if (!f.isFile()) {
            return out;
        }
        try {
            String text = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
            Matcher m = UUID_FIELD.matcher(text);
            while (m.find()) {
                out.add(m.group(1).toLowerCase());
            }
        } catch (Exception ignored) {
            // best-effort
        }
        return out;
    }

    private static final Pattern UUID_FIELD = Pattern.compile("\"uuid\"\\s*:\\s*\"([^\"]+)\"");

    /** SHA-256 (hex) of every .jar in the plugins folder, keyed by file name (sorted, stable). */
    TreeMap<String, String> pluginJarHashes() {
        TreeMap<String, String> out = new TreeMap<>();
        File[] jars = pluginsDir().listFiles(new FilenameFilter() {
            public boolean accept(File d, String name) {
                return name.toLowerCase().endsWith(".jar");
            }
        });
        if (jars == null) {
            return out;
        }
        for (File jar : jars) {
            String h = sha256(jar);
            if (h != null) {
                out.put(jar.getName(), h);
            }
        }
        return out;
    }

    private static String sha256(File f) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[8192];
            try (FileInputStream in = new FileInputStream(f)) {
                int n;
                while ((n = in.read(buf)) != -1) {
                    md.update(buf, 0, n);
                }
            }
            byte[] d = md.digest();
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) {
                sb.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
            }
            return sb.toString();
        } catch (Exception ex) {
            return null;
        }
    }

    /**
     * Whether "others" (any other OS user) can read / write a file. Returns null when the OS
     * doesn't expose POSIX permissions (e.g. Windows) so the caller can skip cleanly.
     */
    Boolean othersCanRead(File f) {
        return posix(f, PosixFilePermission.OTHERS_READ);
    }

    Boolean othersCanWrite(File f) {
        return posix(f, PosixFilePermission.OTHERS_WRITE);
    }

    private static Boolean posix(File f, PosixFilePermission perm) {
        if (f == null || !f.exists()) {
            return null;
        }
        try {
            return Files.getPosixFilePermissions(f.toPath()).contains(perm);
        } catch (UnsupportedOperationException notPosix) {
            return null; // non-POSIX filesystem (Windows) - not evaluable
        } catch (Exception ex) {
            return null;
        }
    }

    // ---------- host / system (read-only; used by the consent-gated system scan) ----------

    /** The OS user the server process runs as (e.g. "minecraft", "root"), or "" if unknown. */
    String osUser() {
        return System.getProperty("user.name", "").trim();
    }

    /** True if the process is (almost certainly) running as the Unix superuser. */
    boolean runningAsRoot() {
        return "root".equalsIgnoreCase(osUser());
    }

    /** The JVM's launch arguments (e.g. -Xmx flags), or an empty list if they can't be read. */
    java.util.List<String> jvmArgs() {
        try {
            return java.lang.management.ManagementFactory.getRuntimeMXBean().getInputArguments();
        } catch (Exception ex) {
            return java.util.Collections.emptyList();
        }
    }

    /** The JVM's maximum heap in bytes (-Xmx), or -1 if unbounded/unknown. */
    long maxHeapBytes() {
        try {
            long m = Runtime.getRuntime().maxMemory();
            return m == Long.MAX_VALUE ? -1 : m;
        } catch (Exception ex) {
            return -1;
        }
    }

    /** Total physical RAM in bytes, via the platform MXBean (reflection, HotSpot-specific), or -1. */
    long physicalRamBytes() {
        Object bean = java.lang.management.ManagementFactory.getOperatingSystemMXBean();
        for (String method : new String[]{"getTotalMemorySize", "getTotalPhysicalMemorySize"}) {
            try {
                java.lang.reflect.Method m = bean.getClass().getMethod(method);
                m.setAccessible(true);
                Object v = m.invoke(bean);
                if (v instanceof Number) {
                    long bytes = ((Number) v).longValue();
                    if (bytes > 0) {
                        return bytes;
                    }
                }
            } catch (Exception ignored) {
                // try the next name; not all JVMs expose either
            }
        }
        return -1;
    }

    /** server.properties as a Properties object (empty if it can't be read). */
    Properties serverProperties() {
        Properties p = new Properties();
        File f = new File(root, "server.properties");
        if (f.isFile()) {
            try (FileInputStream in = new FileInputStream(f)) {
                p.load(in);
            } catch (Exception ignored) {
                // leave empty
            }
        }
        return p;
    }

    /** Loads the first of the given YAML files that exists, or null. */
    YamlConfiguration yaml(String... candidates) {
        for (String name : candidates) {
            File f = new File(root, name);
            if (f.isFile()) {
                return YamlConfiguration.loadConfiguration(f);
            }
        }
        return null;
    }

    /** The plugin name declared inside a jar's plugin.yml, or null. */
    static String pluginName(File jar) {
        try (ZipFile zip = new ZipFile(jar)) {
            ZipEntry entry = zip.getEntry("plugin.yml");
            if (entry == null) {
                return null;
            }
            try (InputStreamReader reader = new InputStreamReader(zip.getInputStream(entry), StandardCharsets.UTF_8)) {
                return YamlConfiguration.loadConfiguration(reader).getString("name");
            }
        } catch (Exception ex) {
            return null;
        }
    }
}
