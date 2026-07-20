package es.cobayka.bulwark;

import org.bukkit.Bukkit;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.util.Arrays;
import java.util.Locale;

final class ServerProfile {

    final String brand;
    final String mcVersion;
    final int mcMajor;
    final int mcMinor;
    final int mcPatch;
    final String platform;
    final String loader;
    final String loaderVersion;
    final boolean folia;
    final boolean paper;
    final boolean hybridForge;
    final boolean moddedArtifacts;
    final boolean moddedRuntime;
    final boolean behindProxy;
    final String proxyType;
    final boolean privateServer;
    final boolean onlineMode;
    final String hosting;

    private ServerProfile(JavaPlugin plugin, ServerEnv env) {
        this.brand = safeBrand();
        this.mcVersion = mcVersion(plugin);
        int[] v = parseMc(this.mcVersion);
        this.mcMajor = v[0];
        this.mcMinor = v[1];
        this.mcPatch = v[2];

        String brandLower = brand.toLowerCase(Locale.ROOT);
        this.moddedArtifacts = hasMods(env);
        this.folia = classExists("io.papermc.paper.threadedregions.RegionizedServer");
        boolean purpur = env.file("purpur.yml").isFile() || classExists("org.purpurmc.purpur.PurpurConfig");
        this.paper = env.yaml("config/paper-global.yml", "paper-global.yml", "paper.yml") != null
                || classExists("io.papermc.paper.configuration.Configuration")
                || classExists("com.destroystokyo.paper.PaperConfig");
        boolean forge = forgeRuntime(env);
        boolean neoForge = neoForgeRuntime(env);
        boolean fabric = fabricRuntime(env);
        boolean quilt = quiltRuntime(env);
        boolean hybridBrand = containsAny(brandLower,
                "arclight", "mohist", "magma", "youer", "banner", "catserver", "cauldron", "kcauldron",
                "thermos", "crucible");
        this.hybridForge = hybridBrand || ((forge || neoForge) && moddedArtifacts);
        LoaderInfo loaderInfo = detectLoader(env, brandLower, hybridBrand, forge, neoForge, fabric, quilt);
        this.loader = loaderInfo.name;
        this.loaderVersion = loaderInfo.version;
        this.moddedRuntime = loaderInfo.modded;

        if (folia) {
            this.platform = "Folia";
        } else if (hybridForge) {
            this.platform = brand + " (modded Bukkit)";
        } else if (purpur) {
            this.platform = "Purpur";
        } else if (paper) {
            this.platform = "Paper";
        } else {
            this.platform = brand;
        }

        String[] proxy = detectProxy(env);
        this.behindProxy = !proxy[0].isEmpty();
        this.proxyType = proxy[0];

        this.privateServer = whitelisted(env);
        this.onlineMode = !"false".equalsIgnoreCase(env.prop("online-mode"));

        this.hosting = detectHosting();
    }

    static ServerProfile detect(JavaPlugin plugin, ServerEnv env) {
        return new ServerProfile(plugin, env);
    }

    boolean managedHosting() {
        return !"VPS / bare-metal".equals(hosting);
    }

    boolean moddedRuntime() {
        return moddedRuntime;
    }

    boolean atLeast(int major, int minor, int patch) {
        if (mcMajor == 0) {
            return true;
        }
        if (mcMajor != major) {
            return mcMajor > major;
        }
        if (mcMinor != minor) {
            return mcMinor > minor;
        }
        return mcPatch >= patch;
    }

    String oneLine() {
        StringBuilder sb = new StringBuilder();
        sb.append(platform);
        if (!mcVersion.isEmpty()) {
            sb.append(" ").append(mcVersion);
        }
        sb.append(" - ").append(loaderLine());
        sb.append(" - ").append(behindProxy
                ? Messages.t("profile.behind-proxy", "behind {0} proxy", proxyType)
                : Messages.t("profile.standalone", "standalone"));
        sb.append(" - ").append(onlineMode
                ? Messages.t("profile.online", "online-mode")
                : Messages.t("profile.offline", "offline-mode"));
        sb.append(" - ").append(privateServer
                ? Messages.t("profile.whitelist-on", "whitelist on")
                : Messages.t("profile.public", "public"));
        sb.append(" - ").append(hosting);
        return sb.toString();
    }

    String loaderLine() {
        StringBuilder sb = new StringBuilder(loader);
        if (!loaderVersion.isEmpty()) {
            sb.append(" ").append(loaderVersion);
        }
        if (moddedArtifacts && !moddedRuntime) {
            sb.append(" (mods folder present; loader not confirmed)");
        }
        return sb.toString();
    }

    private static int[] parseMc(String mc) {
        int[] out = {0, 0, 0};
        if (mc == null) {
            return out;
        }
        String[] parts = mc.trim().split("\\.");
        for (int i = 0; i < parts.length && i < 3; i++) {
            try {
                out[i] = Integer.parseInt(parts[i].replaceAll("[^0-9]", ""));
            } catch (NumberFormatException ignored) {
            }
        }
        return out;
    }

    private static String safeBrand() {
        try {
            String n = Bukkit.getServer().getName();
            return n == null ? "Unknown" : n;
        } catch (Throwable t) {
            return "Unknown";
        }
    }

    private static String mcVersion(JavaPlugin plugin) {
        try {
            String bv = plugin.getServer().getBukkitVersion();
            return bv == null ? "" : bv.split("-")[0];
        } catch (Throwable t) {
            return "";
        }
    }

    private static boolean classExists(String name) {
        try {
            Class.forName(name);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    private static boolean hasMods(ServerEnv env) {
        File mods = env.file("mods");
        if (!mods.isDirectory()) {
            return false;
        }
        File[] jars = mods.listFiles();
        if (jars == null) {
            return false;
        }
        for (File f : jars) {
            if (f.getName().toLowerCase(Locale.ROOT).endsWith(".jar")) {
                return true;
            }
        }
        return false;
    }

    private static boolean forgeRuntime(ServerEnv env) {
        return classExists("net.minecraftforge.fml.loading.FMLLoader")
                || classExists("net.minecraftforge.fml.common.Mod")
                || classExists("cpw.mods.fml.common.Loader")
                || env.file("libraries/net/minecraftforge/forge").isDirectory();
    }

    private static boolean neoForgeRuntime(ServerEnv env) {
        return classExists("net.neoforged.fml.loading.FMLLoader")
                || classExists("net.neoforged.neoforge.common.NeoForge")
                || env.file("libraries/net/neoforged/neoforge").isDirectory();
    }

    private static boolean fabricRuntime(ServerEnv env) {
        return classExists("net.fabricmc.loader.api.FabricLoader")
                || env.file("libraries/net/fabricmc/fabric-loader").isDirectory()
                || env.file("fabric-server-launch.jar").isFile();
    }

    private static boolean quiltRuntime(ServerEnv env) {
        return classExists("org.quiltmc.loader.api.QuiltLoader")
                || env.file("libraries/org/quiltmc/quilt-loader").isDirectory();
    }

    private static LoaderInfo detectLoader(ServerEnv env, String brandLower, boolean hybridBrand,
                                           boolean forge, boolean neoForge, boolean fabric, boolean quilt) {
        if (hybridBrand || forge || neoForge) {
            String name = hybridName(brandLower);
            if (name.isEmpty()) {
                name = neoForge ? "NeoForge/Bukkit hybrid" : "Forge/Bukkit hybrid";
            } else {
                name = name + " hybrid";
            }
            String version = firstNonEmpty(
                    libraryVersion(env, "libraries/net/neoforged/neoforge"),
                    libraryVersion(env, "libraries/net/minecraftforge/forge"),
                    rootJarVersion(env, "mohist", "arclight", "magma", "youer", "banner", "catserver",
                            "cauldron", "kcauldron", "thermos", "crucible", "forge", "neoforge"));
            return new LoaderInfo(name, version, true);
        }
        if (quilt) {
            return new LoaderInfo("Quilt", firstNonEmpty(
                    libraryVersion(env, "libraries/org/quiltmc/quilt-loader"),
                    rootJarVersion(env, "quilt")), true);
        }
        if (fabric) {
            return new LoaderInfo("Fabric", firstNonEmpty(
                    libraryVersion(env, "libraries/net/fabricmc/fabric-loader"),
                    fabricRootVersion(env)), true);
        }
        return new LoaderInfo("Bukkit plugin loader", "", false);
    }

    private static String hybridName(String brandLower) {
        for (String name : new String[]{"arclight", "mohist", "magma", "youer", "banner", "catserver",
                "cauldron", "kcauldron", "thermos", "crucible"}) {
            if (brandLower.contains(name)) {
                return pretty(name);
            }
        }
        return "";
    }

    private static String pretty(String value) {
        if ("kcauldron".equals(value)) {
            return "KCauldron";
        }
        if ("catserver".equals(value)) {
            return "CatServer";
        }
        if (value.isEmpty()) {
            return value;
        }
        return Character.toUpperCase(value.charAt(0)) + value.substring(1);
    }

    private static String libraryVersion(ServerEnv env, String path) {
        File dir = env.file(path);
        if (!dir.isDirectory()) {
            return "";
        }
        File[] children = dir.listFiles(File::isDirectory);
        if (children == null || children.length == 0) {
            return "";
        }
        Arrays.sort(children, (a, b) -> a.getName().compareToIgnoreCase(b.getName()));
        return children[children.length - 1].getName();
    }

    private static String fabricRootVersion(ServerEnv env) {
        String name = rootJarVersion(env, "fabric-server");
        int i = name.indexOf("loader.");
        if (i >= 0) {
            String v = name.substring(i + "loader.".length());
            int dash = v.indexOf('-');
            return dash >= 0 ? v.substring(0, dash) : v;
        }
        return name;
    }

    private static String rootJarVersion(ServerEnv env, String... needles) {
        File[] jars = env.root().listFiles((d, name) -> name.toLowerCase(Locale.ROOT).endsWith(".jar"));
        if (jars == null) {
            return "";
        }
        Arrays.sort(jars, (a, b) -> a.getName().compareToIgnoreCase(b.getName()));
        for (File jar : jars) {
            String n = jar.getName().toLowerCase(Locale.ROOT);
            if (!containsAny(n, needles)) {
                continue;
            }
            String stripped = jar.getName().substring(0, jar.getName().length() - 4);
            int firstDigit = firstDigit(stripped);
            return firstDigit >= 0 ? stripped.substring(firstDigit) : stripped;
        }
        return "";
    }

    private static int firstDigit(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (Character.isDigit(value.charAt(i))) {
                return i;
            }
        }
        return -1;
    }

    private static String[] detectProxy(ServerEnv env) {
        org.bukkit.configuration.file.YamlConfiguration spigot = env.yaml("spigot.yml");
        if (spigot != null && spigot.getBoolean("settings.bungeecord", false)) {
            return new String[]{"BungeeCord"};
        }
        org.bukkit.configuration.file.YamlConfiguration paper =
                env.yaml("config/paper-global.yml", "paper-global.yml", "paper.yml");
        if (paper != null && (paper.getBoolean("proxies.velocity.enabled", false)
                || paper.getBoolean("settings.velocity-support.enabled", false))) {
            return new String[]{"Velocity"};
        }
        return new String[]{""};
    }

    private static String detectHosting() {
        try {
            if (System.getenv("P_SERVER_UUID") != null) {
                return "Pterodactyl";
            }
        } catch (Throwable ignored) {
        }
        if (new File("/.dockerenv").exists() || new File("/run/.containerenv").exists()) {
            return "container";
        }
        return "VPS / bare-metal";
    }

    private static boolean whitelisted(ServerEnv env) {
        try {
            return Bukkit.getServer().hasWhitelist();
        } catch (Throwable t) {
            return "true".equalsIgnoreCase(env.prop("white-list"));
        }
    }

    private static boolean containsAny(String s, String... needles) {
        for (String n : needles) {
            if (s.contains(n)) {
                return true;
            }
        }
        return false;
    }

    private static String firstNonEmpty(String... values) {
        for (String value : values) {
            if (value != null && !value.trim().isEmpty()) {
                return value.trim();
            }
        }
        return "";
    }

    private static final class LoaderInfo {
        final String name;
        final String version;
        final boolean modded;

        LoaderInfo(String name, String version, boolean modded) {
            this.name = name;
            this.version = version;
            this.modded = modded;
        }
    }
}
