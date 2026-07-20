package es.cobayka.bulwark;

import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

final class MinecraftInventory {

    private static final long CACHE_MS = 30_000L;
    private static final int MAX_META = 65_536;
    private static final Pattern JSON_ID = Pattern.compile("\"(?:id|modid)\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern JSON_NAME = Pattern.compile("\"name\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern JSON_VERSION = Pattern.compile("\"version\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern TOML_ID = Pattern.compile("(?m)^\\s*modId\\s*=\\s*\"([^\"]+)\"");
    private static final Pattern TOML_NAME = Pattern.compile("(?m)^\\s*displayName\\s*=\\s*\"([^\"]+)\"");
    private static final Pattern TOML_VERSION = Pattern.compile("(?m)^\\s*version\\s*=\\s*\"([^\"]+)\"");

    static final class Item {
        final String type;
        final String loader;
        final String name;
        final String version;
        final String path;
        final String hash;
        final int functions;
        final List<String> flags;

        Item(String type, String loader, String name, String version, String path, String hash, int functions, List<String> flags) {
            this.type = type;
            this.loader = loader;
            this.name = name;
            this.version = version;
            this.path = path;
            this.hash = hash;
            this.functions = functions;
            this.flags = Collections.unmodifiableList(new ArrayList<>(flags));
        }

        boolean flagged() {
            return !flags.isEmpty();
        }

        boolean jar() {
            String p = path.toLowerCase(Locale.ROOT);
            return p.endsWith(".jar") || p.endsWith(".jar.disabled");
        }
    }

    static final class Result {
        final List<Item> items;

        Result(List<Item> items) {
            this.items = Collections.unmodifiableList(items);
        }

        int count(String type) {
            int n = 0;
            for (Item i : items) {
                if (type.equals(i.type)) {
                    n++;
                }
            }
            return n;
        }

        int flagged() {
            int n = 0;
            for (Item i : items) {
                if (i.flagged()) {
                    n++;
                }
            }
            return n;
        }

        List<Item> flaggedItems() {
            List<Item> out = new ArrayList<>();
            for (Item i : items) {
                if (i.flagged()) {
                    out.add(i);
                }
            }
            return out;
        }

        int functions() {
            int n = 0;
            for (Item i : items) {
                n += i.functions;
            }
            return n;
        }

        String summary() {
            return count("plugin") + " plugins, " + count("mod") + " mods, "
                    + count("datapack") + " datapacks, " + count("resource-pack") + " resource packs, "
                    + count("server-jar") + " root jars, " + count("startup") + " startup files";
        }
    }

    private static final class Meta {
        final String type;
        final String loader;
        final String name;
        final String version;

        Meta(String type, String loader, String name, String version) {
            this.type = type;
            this.loader = loader;
            this.name = name;
            this.version = version;
        }
    }

    private final JavaPlugin plugin;
    private final ServerEnv env;
    private volatile Result cache;
    private volatile long cacheAt;

    MinecraftInventory(JavaPlugin plugin, ServerEnv env) {
        this.plugin = plugin;
        this.env = env;
    }

    Result scan() {
        long now = System.currentTimeMillis();
        Result c = cache;
        if (c != null && now - cacheAt < CACHE_MS) {
            return c;
        }
        List<Item> out = new ArrayList<>();
        scanJarFolder(out, env.pluginsDir(), "plugins");
        scanJarFolder(out, env.file("mods"), "mods");
        scanRootJars(out);
        scanDatapacks(out);
        scanResourcePack(out);
        scanStartup(out);
        out.sort((a, b) -> a.path.compareToIgnoreCase(b.path));
        Result r = new Result(out);
        cache = r;
        cacheAt = now;
        return r;
    }

    private void scanJarFolder(List<Item> out, File dir, String scope) {
        File[] files = dir.listFiles((d, name) -> {
            String n = name.toLowerCase(Locale.ROOT);
            return n.endsWith(".jar") || n.endsWith(".jar.disabled");
        });
        if (files == null) {
            return;
        }
        for (File f : files) {
            try {
                out.add(jarItem(f, scope));
            } catch (Throwable ignored) {
                out.add(simple(f, "jar", "unknown", stripJar(f.getName()), "", scope, flags("unreadable jar")));
            }
        }
    }

    private void scanRootJars(List<Item> out) {
        File[] files = env.root().listFiles((d, name) -> {
            String n = name.toLowerCase(Locale.ROOT);
            return n.endsWith(".jar") || n.endsWith(".jar.disabled");
        });
        if (files == null) {
            return;
        }
        for (File f : files) {
            try {
                Item item = jarItem(f, "root");
                List<String> flags = new ArrayList<>(item.flags);
                String type = item.type;
                if ("plugin".equals(type) || "mod".equals(type) || "hybrid".equals(type)) {
                    flags.add("loadable metadata outside plugins/ or mods/");
                } else {
                    type = "server-jar";
                }
                out.add(new Item(type, item.loader, item.name, item.version, item.path, item.hash, item.functions, flags));
            } catch (Throwable ignored) {
                out.add(simple(f, "server-jar", "unknown", stripJar(f.getName()), "", "root", new ArrayList<String>()));
            }
        }
    }

    private Item jarItem(File f, String scope) throws Exception {
        List<String> flags = new ArrayList<>();
        if (f.getName().toLowerCase(Locale.ROOT).endsWith(".jar.disabled")) {
            flags.add("disabled");
        }
        List<Meta> metas = new ArrayList<>();
        try (ZipFile zip = new ZipFile(f)) {
            addYamlMeta(zip, metas, "paper-plugin.yml", "plugin", "Paper");
            addYamlMeta(zip, metas, "plugin.yml", "plugin", "Bukkit");
            addYamlMeta(zip, metas, "bungee.yml", "plugin", "BungeeCord");
            addJsonMeta(zip, metas, "velocity-plugin.json", "plugin", "Velocity");
            addJsonMeta(zip, metas, "fabric.mod.json", "mod", "Fabric");
            addJsonMeta(zip, metas, "quilt.mod.json", "mod", "Quilt");
            addJsonMeta(zip, metas, "quilt.mod.json5", "mod", "Quilt");
            addTomlMeta(zip, metas, "META-INF/mods.toml", "mod", "Forge");
            addTomlMeta(zip, metas, "META-INF/neoforge.mods.toml", "mod", "NeoForge");
            addJsonMeta(zip, metas, "mcmod.info", "mod", "Legacy Forge");
            addJsonMeta(zip, metas, "litemod.json", "mod", "LiteLoader");
            addJsonMeta(zip, metas, "META-INF/sponge_plugins.json", "plugin", "Sponge");
        }
        Meta meta = primary(metas);
        String type = meta == null ? "jar" : meta.type;
        if (mixed(metas)) {
            type = "hybrid";
            flags.add("contains multiple loader descriptors");
        }
        if ("plugins".equals(scope)) {
            if ("mod".equals(type) || "hybrid".equals(type)) {
                flags.add("mod metadata in plugins/");
            }
            if (meta != null && ("BungeeCord".equals(meta.loader) || "Velocity".equals(meta.loader))) {
                flags.add("proxy plugin in Bukkit plugins/");
            }
            if (meta == null) {
                flags.add("no known Minecraft plugin metadata");
            }
        } else if ("mods".equals(scope)) {
            if ("plugin".equals(type) || "hybrid".equals(type)) {
                flags.add("plugin metadata in mods/");
            }
            if (meta == null) {
                flags.add("no known Minecraft mod metadata");
            }
        }
        if (meta != null && (meta.loader.contains("Legacy") || "LiteLoader".equals(meta.loader))) {
            flags.add("legacy loader metadata");
        }
        writableFlag(f, flags);
        return new Item(type,
                meta == null ? "unknown" : meta.loader,
                meta == null ? stripJar(f.getName()) : value(meta.name, stripJar(f.getName())),
                meta == null ? "" : value(meta.version, ""),
                rel(f),
                shortHash(sha256(f)),
                0,
                flags);
    }

    private void scanDatapacks(List<Item> out) {
        for (File world : worlds()) {
            File dir = new File(world, "datapacks");
            File[] packs = dir.listFiles();
            if (packs == null) {
                continue;
            }
            for (File p : packs) {
                if (!p.isDirectory() && !p.getName().toLowerCase(Locale.ROOT).endsWith(".zip")) {
                    continue;
                }
                List<String> flags = new ArrayList<>();
                boolean ok = packMcmeta(p);
                int functions = functionCount(p);
                if (!ok) {
                    flags.add("missing pack.mcmeta");
                }
                if (functions > 0) {
                    flags.add(functions + " function file(s)");
                }
                writableFlag(p, flags);
                out.add(new Item("datapack", "Vanilla", p.getName(), "", rel(p), "", functions, flags));
            }
        }
    }

    private void scanResourcePack(List<Item> out) {
        String url = env.prop("resource-pack");
        if (url.isEmpty()) {
            return;
        }
        List<String> flags = new ArrayList<>();
        if (env.prop("resource-pack-sha1").isEmpty()) {
            flags.add("missing resource-pack-sha1");
        }
        out.add(new Item("resource-pack", "Vanilla", nameFromUrl(url), "", "server.properties:resource-pack", "", 0, flags));
    }

    private void scanStartup(List<Item> out) {
        for (String name : new String[]{"start.sh", "run.sh", "start.bat", "run.bat", "start.ps1", "run.ps1", "user_jvm_args.txt"}) {
            File f = env.file(name);
            if (!f.isFile()) {
                continue;
            }
            List<String> flags = new ArrayList<>();
            writableFlag(f, flags);
            out.add(new Item("startup", "host", name, "", rel(f), "", 0, flags));
        }
    }

    private Set<File> worlds() {
        Set<File> out = new LinkedHashSet<>();
        String level = env.prop("level-name");
        if (level.isEmpty()) {
            level = "world";
        }
        File primary = env.file(level);
        if (primary.isDirectory()) {
            out.add(primary);
        }
        File[] dirs = env.root().listFiles(File::isDirectory);
        if (dirs != null) {
            for (File d : dirs) {
                if (new File(d, "level.dat").isFile()) {
                    out.add(d);
                }
            }
        }
        return out;
    }

    private boolean packMcmeta(File p) {
        if (p.isDirectory()) {
            return new File(p, "pack.mcmeta").isFile();
        }
        try (ZipFile zip = new ZipFile(p)) {
            return zip.getEntry("pack.mcmeta") != null;
        } catch (Exception ex) {
            return false;
        }
    }

    private int functionCount(File p) {
        try {
            if (p.isDirectory()) {
                final int[] n = {0};
                try (java.util.stream.Stream<Path> walk = Files.walk(p.toPath())) {
                    walk.limit(2000).forEach(path -> {
                        if (path.getFileName() != null && path.getFileName().toString().endsWith(".mcfunction")) {
                            n[0]++;
                        }
                    });
                }
                return n[0];
            }
            int n = 0;
            try (ZipFile zip = new ZipFile(p)) {
                java.util.Enumeration<? extends ZipEntry> entries = zip.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry e = entries.nextElement();
                    if (!e.isDirectory() && e.getName().endsWith(".mcfunction")) {
                        n++;
                    }
                }
            }
            return n;
        } catch (Exception ex) {
            return 0;
        }
    }

    private void addYamlMeta(ZipFile zip, List<Meta> metas, String entry, String type, String loader) {
        ZipEntry e = zip.getEntry(entry);
        if (e == null) {
            return;
        }
        try (InputStream in = zip.getInputStream(e)) {
            byte[] bytes = readLimited(in);
            YamlConfiguration y = YamlConfiguration.loadConfiguration(new InputStreamReader(new ByteArrayInputStream(bytes), StandardCharsets.UTF_8));
            metas.add(new Meta(type, loader, y.getString("name", ""), y.getString("version", "")));
        } catch (Exception ignored) {
            metas.add(new Meta(type, loader, "", ""));
        }
    }

    private void addJsonMeta(ZipFile zip, List<Meta> metas, String entry, String type, String loader) {
        ZipEntry e = zip.getEntry(entry);
        if (e == null) {
            return;
        }
        String text = readZipText(zip, e);
        metas.add(new Meta(type, loader, first(JSON_NAME, text, first(JSON_ID, text, "")), first(JSON_VERSION, text, "")));
    }

    private void addTomlMeta(ZipFile zip, List<Meta> metas, String entry, String type, String loader) {
        ZipEntry e = zip.getEntry(entry);
        if (e == null) {
            return;
        }
        String text = readZipText(zip, e);
        metas.add(new Meta(type, loader, first(TOML_NAME, text, first(TOML_ID, text, "")), first(TOML_VERSION, text, "")));
    }

    private static Meta primary(List<Meta> metas) {
        return metas.isEmpty() ? null : metas.get(0);
    }

    private static boolean mixed(List<Meta> metas) {
        boolean plugin = false;
        boolean mod = false;
        for (Meta m : metas) {
            plugin |= "plugin".equals(m.type);
            mod |= "mod".equals(m.type);
        }
        return plugin && mod;
    }

    private void writableFlag(File f, List<String> flags) {
        Boolean w = env.othersCanWrite(f);
        if (w != null && w) {
            flags.add("world-writable");
        }
    }

    private Item simple(File f, String type, String loader, String name, String version, String scope, List<String> flags) {
        writableFlag(f, flags);
        return new Item(type, loader, name, version, rel(f), f.isFile() ? shortHash(sha256(f)) : "", 0, flags);
    }

    private String rel(File f) {
        try {
            Path root = env.root().getCanonicalFile().toPath();
            Path path = f.getCanonicalFile().toPath();
            return root.relativize(path).toString().replace('\\', '/');
        } catch (Exception ex) {
            return f.getPath().replace('\\', '/');
        }
    }

    private static String stripJar(String name) {
        String n = name;
        if (n.toLowerCase(Locale.ROOT).endsWith(".disabled")) {
            n = n.substring(0, n.length() - ".disabled".length());
        }
        return n.toLowerCase(Locale.ROOT).endsWith(".jar") ? n.substring(0, n.length() - 4) : n;
    }

    private static String nameFromUrl(String url) {
        int q = url.indexOf('?');
        if (q >= 0) {
            url = url.substring(0, q);
        }
        int slash = Math.max(url.lastIndexOf('/'), url.lastIndexOf('\\'));
        return slash >= 0 && slash + 1 < url.length() ? url.substring(slash + 1) : url;
    }

    private static String value(String s, String def) {
        return s == null || s.trim().isEmpty() ? def : s.trim();
    }

    private static List<String> flags(String one) {
        List<String> out = new ArrayList<>();
        out.add(one);
        return out;
    }

    private static String first(Pattern pattern, String text, String fallback) {
        if (text == null) {
            return fallback;
        }
        Matcher m = pattern.matcher(text);
        return m.find() ? m.group(1).trim() : fallback;
    }

    private static String readZipText(ZipFile zip, ZipEntry e) {
        try (InputStream in = zip.getInputStream(e)) {
            return new String(readLimited(in), StandardCharsets.UTF_8);
        } catch (Exception ex) {
            return "";
        }
    }

    private static byte[] readLimited(InputStream in) throws Exception {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int total = 0;
        int n;
        while ((n = in.read(buf)) != -1 && total < MAX_META) {
            int take = Math.min(n, MAX_META - total);
            out.write(buf, 0, take);
            total += take;
        }
        return out.toByteArray();
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
            return "";
        }
    }

    static String shortHash(String hash) {
        return hash == null || hash.length() < 12 ? "" : hash.substring(0, 12);
    }
}
