package es.cobayka.bulwark;

import java.util.Arrays;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Knows which security/protection plugins exist, grouped by category, and detects which ones are
 * INSTALLED - purely by the plugin.yml name the server reports (lower-cased), never by judging a
 * plugin as malicious. Bulwark uses this two ways: to stop crying wolf when a risk is already
 * mitigated (offline mode + a login plugin), and to recommend filling a gap (no anti-cheat? no
 * change logger?). It's honest funnel: it turns other tools into recommendations, not competitors.
 *
 * Names are matched against the canonical runtime name (e.g. AuthMe registers as "AuthMe", not
 * "AuthMeReloaded"), so they're stored lower-cased here.
 */
final class PluginRegistry {

    enum Category {
        LOGIN("a login/auth plugin"),
        ANTICHEAT("an anti-cheat (Grim, Vulcan...)"),
        ANTIEXPLOIT("an anti-exploit/anti-crash plugin"),
        ANTIVPN("an AntiVPN plugin"),
        MALWARE_SCAN("a plugin malware scanner"),
        OPGUARD("an op-guard"),
        PERMISSIONS("a permissions plugin (LuckPerms)"),
        BACKUP("a backup plugin"),
        LOGGING("a change logger (CoreProtect)"),
        PROXY_AUTH("proxy-forwarding protection (BungeeGuard)"),
        ANTIGRIEF("a region/anti-grief plugin");

        final String human;

        Category(String human) {
            this.human = human;
        }
    }

    private static final Map<Category, Set<String>> CATALOG = new EnumMap<>(Category.class);

    private static void put(Category c, String... names) {
        Set<String> s = new LinkedHashSet<>();
        for (String n : names) {
            s.add(n.toLowerCase(java.util.Locale.ROOT));
        }
        CATALOG.put(c, s);
    }

    static {
        put(Category.LOGIN, "authme", "nlogin", "openlogin", "librelogin", "loginsecurity",
                "jpremium", "fastlogin", "limboauth", "ultraauthenticator", "dynamiclogin");
        put(Category.ANTICHEAT, "grimac", "vulcan", "matrix", "spartan", "nocheatplus", "negativity",
                "themis", "polar", "karhu", "intave", "aac", "aacadditionpro");
        put(Category.ANTIEXPLOIT, "exploitfixer", "exploitshield", "serversafeguard", "orebfuscator");
        put(Category.ANTIVPN, "antivpn", "vpnguard", "vpnguardbungee", "advancedantivpn", "ipwhitelist",
                "kaurivpn", "foxgate", "epicguard", "botsentry");
        put(Category.MALWARE_SCAN, "keiko", "mcantimalware", "authority");
        put(Category.OPGUARD, "opguard", "stopop", "antiop");
        put(Category.PERMISSIONS, "luckperms", "permissionsex", "groupmanager", "ultrapermissions", "zpermissions");
        put(Category.BACKUP, "drivebackupv2", "serverbackup", "ultrabackup", "backuper", "easybackups");
        put(Category.LOGGING, "coreprotect", "coreprotectce", "prism", "logblock", "hawkeye");
        put(Category.PROXY_AUTH, "bungeeguard");
        put(Category.ANTIGRIEF, "worldguard", "griefprevention", "griefdefender", "lands", "towny",
                "redprotect", "plotsquared");
    }

    private final Set<String> installed; // lower-cased loaded plugin names

    PluginRegistry(Set<String> loadedPluginNames) {
        this.installed = loadedPluginNames;
    }

    /** Installed plugin names that fall in this category (canonical names from the catalog). */
    Set<String> present(Category c) {
        Set<String> out = new TreeSet<>();
        Set<String> known = CATALOG.get(c);
        if (known != null) {
            for (String name : known) {
                if (installed.contains(name)) {
                    out.add(name);
                }
            }
        }
        return out;
    }

    boolean has(Category c) {
        return !present(c).isEmpty();
    }

    /** True if a plugin with this exact (case-insensitive) runtime name is loaded. */
    boolean installed(String name) {
        return name != null && installed.contains(name.toLowerCase(java.util.Locale.ROOT));
    }

    /** The short category tag for a plugin name (e.g. "login", "anti-cheat"), or "" if uncatalogued. */
    static String categoryLabel(String name) {
        if (name == null) {
            return "";
        }
        String n = name.toLowerCase(java.util.Locale.ROOT);
        for (Map.Entry<Category, Set<String>> e : CATALOG.entrySet()) {
            if (e.getValue().contains(n)) {
                return e.getKey().name().toLowerCase(java.util.Locale.ROOT).replace('_', '-');
            }
        }
        return "";
    }

    /** Pretty list of the protective plugins detected, for the report. */
    String protectionsLine() {
        Set<String> all = new LinkedHashSet<>();
        for (Category c : Arrays.asList(Category.LOGIN, Category.ANTICHEAT, Category.ANTIEXPLOIT,
                Category.ANTIVPN, Category.MALWARE_SCAN, Category.OPGUARD, Category.LOGGING,
                Category.BACKUP, Category.PROXY_AUTH, Category.ANTIGRIEF, Category.PERMISSIONS)) {
            all.addAll(present(c));
        }
        return all.isEmpty() ? Messages.t("profile.no-protections", "none detected") : String.join(", ", all);
    }
}
