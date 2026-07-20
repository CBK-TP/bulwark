package es.cobayka.bulwark;

import org.bukkit.plugin.java.JavaPlugin;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

final class PostureProfile {

    private static final Set<String> VALID = new HashSet<>(Arrays.asList(
            "auto", "public-survival", "private-smp", "minigame", "creative-build", "proxy-backend", "modded"));

    final String configured;
    final String active;
    final boolean automatic;
    final boolean confirmed;
    final boolean invalid;
    final String evidence;

    private PostureProfile(String configured, String active, boolean automatic, boolean confirmed,
                           boolean invalid, String evidence) {
        this.configured = configured;
        this.active = active;
        this.automatic = automatic;
        this.confirmed = confirmed;
        this.invalid = invalid;
        this.evidence = evidence;
    }

    static PostureProfile detect(JavaPlugin plugin, ServerEnv env, ServerProfile server, PluginRegistry reg) {
        String raw = plugin.getConfig().getString("security-profile", "auto");
        String configured = normalize(raw);
        boolean invalid = !VALID.contains(configured);
        boolean auto = invalid || "auto".equals(configured);
        String guessed = guess(server, reg);
        String active = auto ? guessed : configured;
        boolean confirmed = plugin.getConfig().getBoolean("security-profile-confirmed", false);
        return new PostureProfile(configured, active, auto, confirmed, invalid, evidence(server, reg, active));
    }

    boolean is(String id) {
        return active.equals(id);
    }

    String line() {
        String source = automatic ? "auto" : "configured";
        String suffix = confirmed ? ", confirmed" : ", not confirmed";
        return active + " (" + source + suffix + "; " + evidence + ")";
    }

    private static String guess(ServerProfile server, PluginRegistry reg) {
        if (server.behindProxy) {
            return "proxy-backend";
        }
        if (server.privateServer) {
            return "private-smp";
        }
        if (server.moddedRuntime()) {
            return "modded";
        }
        if (reg.has(PluginRegistry.Category.ANTIGRIEF) && !reg.has(PluginRegistry.Category.ANTICHEAT)) {
            return "creative-build";
        }
        return "public-survival";
    }

    private static String evidence(ServerProfile server, PluginRegistry reg, String active) {
        StringBuilder sb = new StringBuilder();
        sb.append(server.platform);
        sb.append(", ").append(server.loaderLine());
        sb.append(server.behindProxy ? ", proxy" : ", standalone");
        sb.append(server.privateServer ? ", whitelist" : ", public");
        if (!server.onlineMode) {
            sb.append(", offline-mode");
        }
        if (reg.installed("geyser-spigot") || reg.installed("geyser") || reg.installed("floodgate")) {
            sb.append(", bedrock-crossplay");
        }
        if ("creative-build".equals(active) && reg.has(PluginRegistry.Category.ANTIGRIEF)) {
            sb.append(", region protection");
        }
        return sb.toString();
    }

    private static String normalize(String value) {
        if (value == null) {
            return "auto";
        }
        String v = value.trim().toLowerCase(Locale.ROOT).replace('_', '-');
        return v.isEmpty() ? "auto" : v;
    }
}
