package es.cobayka.bulwark;

import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

final class ArtifactControl {

    static final class Result {
        final boolean ok;
        final String message;

        Result(boolean ok, String message) {
            this.ok = ok;
            this.message = message;
        }
    }

    private final JavaPlugin plugin;
    private final ServerEnv env;

    ArtifactControl(JavaPlugin plugin, ServerEnv env) {
        this.plugin = plugin;
        this.env = env;
    }

    Result disable(String token) {
        File f = findJar(token, false);
        if (f == null) {
            return new Result(false, "Jar not found or already disabled.");
        }
        File dst = new File(f.getParentFile(), f.getName() + ".disabled");
        if (dst.exists()) {
            return new Result(false, "Disabled target already exists: " + rel(dst));
        }
        if (!f.renameTo(dst)) {
            return new Result(false, "Could not rename " + rel(f) + ".");
        }
        return new Result(true, "Disabled for next restart: " + rel(dst));
    }

    Result enable(String token) {
        File f = findJar(token, true);
        if (f == null) {
            return new Result(false, "Disabled jar not found.");
        }
        String name = f.getName();
        if (!name.endsWith(".disabled")) {
            return new Result(false, "Not a disabled jar: " + rel(f));
        }
        File dst = new File(f.getParentFile(), name.substring(0, name.length() - ".disabled".length()));
        if (dst.exists()) {
            return new Result(false, "Enabled target already exists: " + rel(dst));
        }
        if (!f.renameTo(dst)) {
            return new Result(false, "Could not rename " + rel(f) + ".");
        }
        return new Result(true, "Enabled for next restart: " + rel(dst));
    }

    List<File> configs(String token) {
        File dir = configDir(token);
        List<File> out = new ArrayList<>();
        if (dir == null || !dir.isDirectory()) {
            return out;
        }
        File[] files = dir.listFiles();
        if (files == null) {
            return out;
        }
        for (File f : files) {
            if (f.isFile() && configName(f.getName())) {
                out.add(f);
            }
        }
        out.sort((a, b) -> a.getName().compareToIgnoreCase(b.getName()));
        return out;
    }

    MinecraftInventory.Item item(String token) {
        String low = token.toLowerCase(Locale.ROOT);
        for (MinecraftInventory.Item i : new MinecraftInventory(plugin, env).scan().items) {
            if (i.name.equalsIgnoreCase(token) || i.path.equalsIgnoreCase(token)
                    || i.path.toLowerCase(Locale.ROOT).endsWith("/" + low)
                    || i.path.toLowerCase(Locale.ROOT).endsWith("/" + low + ".jar")
                    || i.path.toLowerCase(Locale.ROOT).endsWith("/" + low + ".jar.disabled")) {
                return i;
            }
        }
        return null;
    }

    private File configDir(String token) {
        try {
            org.bukkit.plugin.Plugin loaded = plugin.getServer().getPluginManager().getPlugin(token);
            if (loaded != null && loaded.getDataFolder() != null) {
                return loaded.getDataFolder();
            }
        } catch (Throwable ignored) {
        }
        File exact = new File(env.pluginsDir(), token);
        if (exact.isDirectory()) {
            return exact;
        }
        File[] dirs = env.pluginsDir().listFiles(File::isDirectory);
        if (dirs != null) {
            for (File d : dirs) {
                if (d.getName().equalsIgnoreCase(token)) {
                    return d;
                }
            }
        }
        return null;
    }

    private File findJar(String token, boolean disabled) {
        String low = token.toLowerCase(Locale.ROOT);
        for (File root : new File[]{env.pluginsDir(), env.file("mods"), env.root()}) {
            File[] files = root.listFiles((d, name) -> {
                String n = name.toLowerCase(Locale.ROOT);
                return disabled ? n.endsWith(".jar.disabled") : n.endsWith(".jar");
            });
            if (files == null) {
                continue;
            }
            for (File f : files) {
                String name = f.getName().toLowerCase(Locale.ROOT);
                String base = name;
                if (base.endsWith(".disabled")) {
                    base = base.substring(0, base.length() - ".disabled".length());
                }
                if (base.endsWith(".jar")) {
                    base = base.substring(0, base.length() - 4);
                }
                if (name.equals(low) || base.equals(low) || rel(f).equalsIgnoreCase(token)) {
                    return f;
                }
                String declared = ServerEnv.pluginName(f);
                if (declared != null && declared.equalsIgnoreCase(token)) {
                    return f;
                }
            }
        }
        return null;
    }

    private static boolean configName(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        return n.endsWith(".yml") || n.endsWith(".yaml") || n.endsWith(".json")
                || n.endsWith(".properties") || n.endsWith(".conf") || n.endsWith(".toml");
    }

    private String rel(File f) {
        try {
            return env.root().getCanonicalFile().toPath().relativize(f.getCanonicalFile().toPath()).toString().replace('\\', '/');
        } catch (Exception ex) {
            return f.getPath().replace('\\', '/');
        }
    }
}
