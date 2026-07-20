package es.cobayka.bulwark;

import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;

final class PluginTrust {

    static final class Delta {
        final String type;
        final String name;
        final String oldHash;
        final String newHash;

        Delta(String type, String name, String oldHash, String newHash) {
            this.type = type;
            this.name = name;
            this.oldHash = oldHash;
            this.newHash = newHash;
        }
    }

    private final JavaPlugin plugin;
    private final ServerEnv env;

    PluginTrust(JavaPlugin plugin, ServerEnv env) {
        this.plugin = plugin;
        this.env = env;
    }

    boolean hasBaseline() {
        return file().isFile() && !trusted().isEmpty();
    }

    int currentCount() {
        return env.pluginJarHashes().size();
    }

    int save() {
        TreeMap<String, String> now = env.pluginJarHashes();
        return write(now) ? now.size() : -1;
    }

    List<Delta> diff() {
        TreeMap<String, String> base = trusted();
        TreeMap<String, String> now = env.pluginJarHashes();
        List<Delta> out = new ArrayList<>();
        if (base.isEmpty()) {
            return out;
        }
        for (String name : base.keySet()) {
            String cur = now.get(name);
            if (cur == null) {
                out.add(new Delta("removed", name, base.get(name), ""));
            } else if (!base.get(name).equalsIgnoreCase(cur)) {
                out.add(new Delta("changed", name, base.get(name), cur));
            }
        }
        for (String name : now.keySet()) {
            if (!base.containsKey(name)) {
                out.add(new Delta("new", name, "", now.get(name)));
            }
        }
        return out;
    }

    TreeMap<String, String> trusted() {
        TreeMap<String, String> out = new TreeMap<>();
        File f = file();
        if (!f.isFile()) {
            return out;
        }
        try {
            for (String line : Files.readAllLines(f.toPath(), StandardCharsets.UTF_8)) {
                int tab = line.indexOf('\t');
                if (tab < 1 || tab == line.length() - 1) {
                    continue;
                }
                String hash = line.substring(0, tab).trim().toLowerCase(java.util.Locale.ROOT);
                String name = line.substring(tab + 1).trim();
                if (hash.matches("[0-9a-f]{64}") && !name.isEmpty()) {
                    out.put(name, hash);
                }
            }
        } catch (Exception ignored) {
            return new TreeMap<>();
        }
        return out;
    }

    static String shortHash(String hash) {
        return hash == null || hash.length() < 12 ? "" : hash.substring(0, 12);
    }

    private File file() {
        return new File(plugin.getDataFolder(), "trusted-plugins.tsv");
    }

    private boolean write(TreeMap<String, String> hashes) {
        plugin.getDataFolder().mkdirs();
        File f = file();
        File tmp = new File(f.getParentFile(), f.getName() + ".tmp");
        try (PrintWriter w = new PrintWriter(new OutputStreamWriter(new FileOutputStream(tmp), StandardCharsets.UTF_8))) {
            for (java.util.Map.Entry<String, String> e : hashes.entrySet()) {
                w.println(e.getValue().toLowerCase(java.util.Locale.ROOT) + "\t" + e.getKey().replace('\t', ' '));
            }
        } catch (Exception ex) {
            return false;
        }
        try {
            Files.move(tmp.toPath(), f.toPath(),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            return true;
        } catch (Exception ex) {
            try {
                Files.move(tmp.toPath(), f.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                return true;
            } catch (Exception ignored) {
                return false;
            }
        }
    }
}
