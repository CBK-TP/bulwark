package es.cobayka.bulwark;

import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.FilenameFilter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/** Runs every check against the server's config and works out a score and grade. */
final class AuditEngine {

    private final JavaPlugin plugin;
    private final ServerEnv env;
    private ServerProfile profile;
    private PostureProfile posture;
    private PluginRegistry reg;

    AuditEngine(JavaPlugin plugin, ServerEnv env) {
        this.plugin = plugin;
        this.env = env;
    }

    /** A per-area sub-grade (one of the Cobayka Hardening Baseline areas). */
    static final class AreaGrade {
        final String name;
        final int score;
        final char grade;
        final int findings;

        AreaGrade(String name, int score, char grade, int findings) {
            this.name = name;
            this.score = score;
            this.grade = grade;
            this.findings = findings;
        }
    }

    /** The outcome of one audit run. */
    static final class Result {
        final List<Finding> findings;
        final int score;
        final char grade;
        final List<AreaGrade> areas;
        final String profile;   // one-line description of the detected environment
        final String posture;
        final boolean consented; // false = no scan was run yet (awaiting /bulwark consent)

        Result(List<Finding> findings, int score, char grade, List<AreaGrade> areas,
               String profile, String posture, boolean consented) {
            this.findings = findings;
            this.score = score;
            this.grade = grade;
            this.areas = areas;
            this.profile = profile;
            this.posture = posture;
            this.consented = consented;
        }
    }

    // Synchronized: a single engine instance is shared across the main thread, the scheduler/drift
    // thread and the web-panel HTTP thread, and run() writes the per-run profile/reg fields. Serialising
    // run() keeps each audit self-consistent and reentrant-safe (audits are fast, file-based).
    synchronized Result run() {
        // Bulwark scans nothing until the admin has given consent (its own config AND the host).
        if (!consented()) {
            Result nc = notConsented();
            lastResult = nc;
            return nc;
        }
        // Detect the environment first - several checks adapt their severity to it.
        profile = ServerProfile.detect(plugin, env);
        reg = new PluginRegistry(env.loadedPluginNames());
        posture = PostureProfile.detect(plugin, env, profile, reg);

        List<Finding> all = new ArrayList<>();
        Properties props = env.serverProperties();

        checkPosture(props, all);
        checkServerProperties(props, all);
        checkOperators(all);
        checkSpigot(all);
        checkPaper(all);
        checkAntiXrayPosture(all);
        checkBukkit(props, all);
        checkCommandSurface(all);
        checkRuntime(all);
        checkDuplicatePlugins(all);
        checkPluginTrust(all);
        checkInventory(props, all);
        // Host/system checks (file permissions, the user we run as, JVM settings) - all read-only
        // and local. These are covered by the same scan consent that gated the whole run.
        checkFilePermissions(all);
        checkSystem(all);
        checkContext(all);

        // Honour the ignore list, then apply any per-check severity overrides - both from config.
        Set<String> ignore = new HashSet<>(plugin.getConfig().getStringList("ignore"));
        ConfigurationSection overrides = plugin.getConfig().getConfigurationSection("severity-overrides");
        List<Finding> findings = new ArrayList<>();
        for (Finding f : all) {
            if (ignore.contains(f.id)) {
                continue;
            }
            findings.add(applyOverride(f, overrides));
        }

        // Global grade + per-area sub-grades. Only SECURITY findings count toward a grade;
        // performance/reliability ("Hardening") notes are advisory.
        Map<String, Integer> areaPenalty = new LinkedHashMap<>();
        Map<String, Integer> areaCount = new LinkedHashMap<>();
        List<String> areaOrder = new ArrayList<>(Baseline.AREAS);
        for (String a : Baseline.AREAS) {
            areaPenalty.put(a, 0);
            areaCount.put(a, 0);
        }
        int penalty = 0;
        for (Finding f : findings) {
            if (!graded(f)) {
                continue;
            }
            penalty += f.severity.penalty;
            String area = f.area;
            if (!areaPenalty.containsKey(area)) {
                areaPenalty.put(area, 0);
                areaCount.put(area, 0);
                areaOrder.add(area);
            }
            areaPenalty.merge(area, f.severity.penalty, Integer::sum);
            areaCount.merge(area, 1, Integer::sum);
        }
        int score = Math.max(0, 100 - penalty);

        List<AreaGrade> areas = new ArrayList<>();
        for (String a : areaOrder) {
            Integer count = areaCount.get(a);
            if (count != null && count > 0) {
                int s = Math.max(0, 100 - areaPenalty.get(a));
                areas.add(new AreaGrade(a, s, gradeOf(s), count));
            }
        }

        findings.sort((a, b) -> a.severity.ordinal() - b.severity.ordinal()); // worst first
        String prof = profile.oneLine() + Messages.t("report.protections", " · protections: ") + reg.protectionsLine();
        String postureLine = posture.line();
        prof = prof + Messages.t("report.posture", " - posture: ") + postureLine;
        Result res = new Result(findings, score, gradeOf(score), areas, prof, postureLine, true);
        lastResult = res;
        return res;
    }

    // Last computed result, so cheap consumers (the web panel) can read the latest audit WITHOUT
    // triggering a fresh file scan on every request. The scheduler / scan-on-start / on-demand run()
    // keep it fresh.
    private volatile Result lastResult;

    /** The last audit result, or runs one if none yet. Read-only consumers should use this, not run().
     *  Re-runs only when there's no cache or the consent state changed since it was cached (a cheap
     *  flag/marker check, never a scan), so a page view normally costs nothing. */
    Result cached() {
        Result r = lastResult;
        if (r == null || r.consented != consented()) {
            return run();
        }
        return r;
    }

    /** True once the admin has authorized scanning (config flag or a .consent marker). */
    boolean consented() {
        if (plugin.getConfig().getBoolean("scan-consent", false)) {
            return true;
        }
        return new File(plugin.getDataFolder(), ".consent").isFile();
    }

    /** The result returned before consent: no scan was performed, just a prompt to authorize one. */
    private Result notConsented() {
        List<Finding> f = new ArrayList<>();
        f.add(new Finding("consent-needed", "reliability", Severity.INFO,
                Messages.finding("consent-needed", "title", "Scan not authorized yet"),
                Messages.finding("consent-needed", "detail", "Bulwark hasn't scanned anything yet. It needs your one-time consent before it reads this server's config, host settings and logs. Logs can contain PII such as chat, player names, IPs and commands; reads are local and read-only."),
                Messages.finding("consent-needed", "fix", "Run /bulwark consent to authorize the scan (you can revoke it any time with /bulwark consent off).")));
        return new Result(f, 0, '-', new ArrayList<AreaGrade>(),
                Messages.t("report.scan-not-authorized", "scan not authorized"), "", false);
    }

    /** Whether a finding counts toward the security grade (performance/reliability don't). */
    static boolean graded(Finding f) {
        return !"log".equals(f.category)
                && !f.id.startsWith("log-")
                && !"performance".equals(f.category) && !"reliability".equals(f.category)
                && !Baseline.HARDENING.equals(f.area);
    }

    private static char gradeOf(int score) {
        return score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
    }

    // ---------- checks ----------

    private void checkPosture(Properties props, List<Finding> l) {
        if (posture.invalid) {
            add(l, "posture-profile-invalid", "reliability", Severity.INFO,
                    "Unknown security profile configured",
                    "security-profile is set to '{0}', which Bulwark does not know. It fell back to auto detection: {1}.",
                    "Set security-profile to auto, public-survival, private-smp, minigame, creative-build, proxy-backend or modded.",
                    posture.configured, posture.line());
        }
        if (posture.automatic) {
            add(l, "posture-profile-auto", "reliability", Severity.INFO,
                    "Security profile inferred automatically",
                    "Bulwark is using the {0} posture profile from local evidence: {1}. Auto profile is visible evidence, not a hidden trust decision.",
                    "If this profile is wrong, set security-profile explicitly in config.yml.",
                    posture.active, posture.evidence);
        } else if (!posture.confirmed) {
            add(l, "posture-profile-unconfirmed", "reliability", Severity.INFO,
                    "Security profile is not confirmed",
                    "security-profile is set to {0}, but security-profile-confirmed is false. Bulwark will show this as configured but not confirmed.",
                    "Set security-profile-confirmed=true after checking that the profile matches this server.",
                    posture.active);
        }

        if (profile.moddedRuntime || profile.moddedArtifacts) {
            add(l, "loader-runtime-detected", "reliability", Severity.INFO,
                    "Runtime loader detected",
                    "Bulwark detected {0}. Loader-aware findings reduce Bukkit/Paper assumptions on modded or hybrid servers.",
                    "Use /bulwark inventory all to review the actual plugin/mod jars, and set security-profile explicitly if this server role is unusual.",
                    profile.loaderLine());
        }

        if (posture.is("private-smp") && equals(props, "white-list", "false")) {
            add(l, "profile-private-whitelist-open", "access", Severity.MEDIUM,
                    "Private SMP profile but whitelist is open",
                    "This server is being treated as private-smp, but white-list=false lets anyone who knows the address join.",
                    "Enable the whitelist and enforce-whitelist, or change security-profile if this server is intentionally public.");
        }

        if (posture.is("proxy-backend") && profile.behindProxy) {
            add(l, "proxy-backend-firewall-unverified", "core", Severity.INFO,
                    "Proxy backend exposure cannot be proven locally",
                    "Bulwark detected a proxy-backend profile. From inside Bukkit it can read forwarding config, but it cannot prove that the backend port is firewalled from the public internet.",
                    "Confirm at the firewall or panel level that only the proxy can reach this backend port.");
        }

        checkFloodgatePosture(l);
    }

    private void checkServerProperties(Properties p, List<Finding> l) {
        if (p.isEmpty()) {
            add(l, "no-server-properties", "core", Severity.INFO,
                    "server.properties not found",
                    "Bulwark couldn't find server.properties next to the server jar, so a few checks were skipped. This is normal on a proxy.",
                    "Run Bulwark on the game server itself, or check file permissions.");
            return;
        }
        boolean proxy = behindProxy();

        if (equals(p, "online-mode", "false")) {
            if (proxy) {
                add(l, "offline-mode-proxy", "core", Severity.INFO,
                        "Offline mode (proxy detected)",
                        "online-mode is false, which is expected when a proxy (BungeeCord/Velocity) handles login.",
                        "Make sure the server port is firewalled so only the proxy can reach it and that modern forwarding (Velocity) or BungeeGuard is enabled - otherwise anyone can connect directly as any player.");
            } else if (reg.has(PluginRegistry.Category.LOGIN)) {
                add(l, "offline-mode-login", "core", Severity.MEDIUM,
                        "Offline mode (a login plugin is handling auth)",
                        "online-mode=false with no proxy, but a login plugin (AuthMe/nLogin/...) is installed to authenticate players. That mitigates the biggest risk - but offline mode is still weaker than real authentication (a leaked password is the only thing protecting an account, and a misconfigured login plugin re-opens the hole).",
                        "Use online-mode=true if you don't specifically need cracked/offline players; otherwise make sure the login plugin enforces registration and strong passwords.");
            } else {
                add(l, "offline-mode", "core", Severity.CRITICAL,
                        "Server is in offline mode",
                        "online-mode=false with no proxy detected and no login plugin found. Anyone can log in as ANY username - including your admins - with no authentication. This is the biggest account-security hole there is.",
                        "Set online-mode=true in server.properties and restart. Only use offline mode behind a properly firewalled proxy, or with a login plugin (AuthMe) that enforces passwords.");
            }
        }

        if (equals(p, "enable-rcon", "true")) {
            int rconMin = plugin.getConfig().getInt("thresholds.rcon-min-password", 12);
            String pw = value(p, "rcon.password");
            if (pw.isEmpty()) {
                add(l, "rcon-no-password", "core", Severity.CRITICAL,
                        "RCON enabled with no password",
                        "Remote console (RCON) is on with an empty password - that's full remote control of your server for anyone who can reach the RCON port.",
                        "Set a long random rcon.password, or turn RCON off (enable-rcon=false) if you don't use it. Never expose the RCON port to the internet.");
            } else if (pw.length() < rconMin) {
                add(l, "rcon-weak-password", "core", Severity.HIGH,
                        "RCON password is weak",
                        "RCON is enabled with a short password ({0} chars), which is brute-forceable.",
                        "Use a 16+ character random password and firewall the RCON port to localhost/admin only.", pw.length());
            } else {
                add(l, "rcon-enabled", "core", Severity.MEDIUM,
                        "RCON is enabled",
                        "Remote console is on. Even with a strong password, an exposed RCON port is a remote-control risk.",
                        "Firewall the RCON port so only you can reach it, or disable it when unused.");
            }
        }

        if (equals(p, "enable-query", "true")) {
            add(l, "query-enabled", "core", Severity.MEDIUM,
                    "Query protocol enabled",
                    "enable-query=true exposes live server info (players, version) to anyone, which attackers use to fingerprint and target servers.",
                    "Set enable-query=false unless a tool you run truly needs it.");
        }

        if (equals(p, "enforce-secure-profile", "false")) {
            add(l, "insecure-chat", "core", Severity.MEDIUM,
                    "Signed chat not enforced",
                    "enforce-secure-profile=false lets clients chat without cryptographically-signed messages (1.19+). That weakens message traceability and the chat-reporting system, and lets non-standard clients that can't sign chat join.",
                    "Set enforce-secure-profile=true unless you specifically need to support clients that can't sign chat.");
        }

        if (equals(p, "white-list", "false")) {
            add(l, "no-whitelist", "access", Severity.LOW,
                    "Whitelist is off",
                    "white-list=false means anyone who knows the address can join. Fine for a public server, risky for a private or staging one.",
                    "Set white-list=true (and enforce-whitelist=true) if this server is meant to be private.");
        } else if (equals(p, "white-list", "true") && equals(p, "enforce-whitelist", "false")) {
            add(l, "whitelist-not-enforced", "access", Severity.LOW,
                    "Whitelist not enforced live",
                    "The whitelist is on but enforce-whitelist=false, so a player removed from it while online isn't kicked.",
                    "Set enforce-whitelist=true so whitelist changes apply immediately.");
        }

        if (equals(p, "rate-limit", "0")) {
            add(l, "no-rate-limit", "core", Severity.LOW,
                    "No packet rate limit (default)",
                    "rate-limit=0 is the stock default and leaves the per-connection packet limit off, so a flood/crasher client isn't dropped by the server itself. Paper has its own packet protections, so treat this as optional hardening, not an open hole.",
                    "Optionally set rate-limit to something like 300 so abusive clients get dropped - test that it doesn't affect normal players.");
        }

        if (equals(p, "spawn-protection", "0")) {
            add(l, "no-spawn-protection", "world", Severity.INFO,
                    "No vanilla spawn protection",
                    "spawn-protection=0 lets non-ops build and break at spawn. That's perfectly fine if you guard spawn with a region plugin (WorldGuard etc.) - flagged just for awareness.",
                    "Set a small radius (e.g. 16), or ignore this if a region plugin already protects spawn.");
        }

        int fpl = intValue(p, "function-permission-level", 2);
        if (fpl > 2) {
            add(l, "high-function-permission-level", "access", Severity.MEDIUM,
                    "Functions run with an elevated permission level ({0})",
                    "function-permission-level={0} gives datapack functions level {0} (3-4 = gamemaster/owner). An untrusted or compromised datapack can then run admin-level commands.",
                    "Set function-permission-level back to 2 unless a datapack you trust truly needs more.", fpl);
        }

        int opl = intValue(p, "op-permission-level", 4);
        if (opl >= 4) {
            add(l, "high-op-permission-level", "access", Severity.INFO,
                    "Operators have the maximum permission level ({0})",
                    "op-permission-level={0} gives every op the highest level, including /stop and command-block/owner commands. That's the default - flagged only so you know you can shrink the blast radius of a compromised op.",
                    "If your ops don't need owner-level commands, set op-permission-level to 3.", opl);
        }

        if (equals(p, "enable-command-block", "true")) {
            add(l, "command-blocks-enabled", "access", Severity.LOW,
                    "Command blocks are enabled",
                    "enable-command-block=true lets command blocks run gamemaster-level commands. Fine for redstone/adventure maps; a wider attack surface on a survival server with many ops or creative access.",
                    "Set enable-command-block=false if your server doesn't use command-block contraptions.");
        }

        String rp = value(p, "resource-pack");
        if (!rp.isEmpty() && value(p, "resource-pack-sha1").isEmpty()) {
            add(l, "resource-pack-no-sha", "core", Severity.MEDIUM,
                    "Resource pack served without a SHA-1",
                    "A resource-pack URL is set but resource-pack-sha1 is empty, so clients can't verify the pack - a man-in-the-middle could swap it for an altered one, and clients re-download it every join.",
                    "Set resource-pack-sha1 to the SHA-1 of the exact pack file you serve.");
        }

        if (equals(p, "prevent-proxy-connections", "false")) {
            add(l, "no-proxy-protection", "core", Severity.INFO,
                    "VPN/proxy connections not blocked (vanilla toggle)",
                    "prevent-proxy-connections=false (the default) leaves Mojang's own proxy check off, so connections through known proxies aren't rejected. This is just the vanilla flag - a dedicated AntiVPN plugin does a far better job.",
                    "Set prevent-proxy-connections=true for a light vanilla check, or run an AntiVPN plugin if ban-evasion/bots are a problem.");
        }

        if (equals(p, "enable-jmx-monitoring", "true")) {
            add(l, "jmx-enabled", "core", Severity.MEDIUM,
                    "JMX monitoring is enabled",
                    "enable-jmx-monitoring=true opens a JMX management interface. If its port is reachable - especially without JMX authentication and TLS - it's a remote-management surface that can leak internals or, in some setups, be turned into remote code execution.",
                    "Set enable-jmx-monitoring=false unless you actively use JMX; if you do, bind it to localhost with authentication and TLS.");
        }

        int maxTick = intValue(p, "max-tick-time", 60000);
        if (maxTick <= 0) {
            add(l, "watchdog-max-tick", "reliability", Severity.LOW,
                    "Server watchdog disabled (max-tick-time)",
                    "max-tick-time={0} turns off the single-tick watchdog, so a hung or deadlocked tick won't trip the crash/restart safeguard - the server can freeze indefinitely instead of recovering.",
                    "Leave max-tick-time at the default (60000) unless you have a specific reason, so a frozen server is caught and restarted.", maxTick);
        }

        // accepts-transfers exists from MC 1.20.5 - only meaningful there (and the key is absent before,
        // so this never false-positives on older servers; the version gate is just for clarity).
        if (profile.atLeast(1, 20, 5) && equals(p, "accepts-transfers", "true")) {
            add(l, "accepts-transfers", "core", Severity.LOW,
                    "Server accepts client transfers",
                    "accepts-transfers=true lets another server hand its connected players to THIS server via the 1.20.5+ transfer packet (carrying a cookie). Only enable it if you run a transfer-based network - otherwise it widens what can reach your server and how much it trusts an upstream server.",
                    "Set accepts-transfers=false unless you specifically use cross-server transfers.");
        }

        // Floodgate/Geyser is built to run with online-mode=true (it authenticates Bedrock itself), so
        // offline mode + Floodgate is a common misconfiguration that weakens Java accounts for nothing.
        boolean floodgate = reg.installed("floodgate") || reg.installed("geyser-spigot") || reg.installed("geyser");
        if (floodgate && equals(p, "online-mode", "false") && !proxy) {
            add(l, "floodgate-online-mode", "core", Severity.LOW,
                    "Floodgate/Geyser running with offline mode",
                    "Floodgate/Geyser is installed but online-mode=false. Floodgate authenticates Bedrock players itself and is designed to run with online-mode=true - it does NOT need offline mode. Running offline here weakens Java-account security for no Bedrock benefit.",
                    "Set online-mode=true and let Floodgate handle Bedrock authentication (per the GeyserMC docs).");
        }

        int maxVd = Math.max(1, plugin.getConfig().getInt("thresholds.max-view-distance", 10));
        int vd = intValue(p, "view-distance", 10);
        if (vd > maxVd) {
            add(l, "high-view-distance", "performance", Severity.MEDIUM,
                    "High view-distance ({0})",
                    "A high view-distance multiplies CPU and bandwidth per player and widens the lag/DoS surface.",
                    "Lower view-distance to {1} or below (6-10 is typical).", vd, maxVd);
        }
        int maxSd = Math.max(1, plugin.getConfig().getInt("thresholds.max-simulation-distance", maxVd));
        int sd = intValue(p, "simulation-distance", 10);
        if (sd > maxSd) {
            add(l, "high-simulation-distance", "performance", Severity.LOW,
                    "High simulation-distance ({0})",
                    "A high simulation-distance increases the per-player tick load.",
                    "Lower simulation-distance to {1} or below.", sd, maxSd);
        }
    }

    private void checkOperators(List<Finding> l) {
        int ops = env.operatorCount();
        if (ops < 0) {
            return; // couldn't read ops.json
        }
        int max = Math.max(1, plugin.getConfig().getInt("thresholds.max-operators", 3));
        if (ops > max) {
            Severity sev = ops > max * 3 ? Severity.HIGH : Severity.MEDIUM;
            add(l, "many-operators", "access", sev,
                    "Many server operators ({0})",
                    "There are {0} ops. Every op has full, unchecked control of the server and console - a large attack surface if any one of those accounts is compromised.",
                    "Keep ops to the few who truly need full control; give everyone else scoped access with a permissions plugin (LuckPerms).", ops);
        }
    }

    private void checkSpigot(List<Finding> l) {
        YamlConfiguration s = env.yaml("spigot.yml");
        if (s == null) {
            return;
        }
        if (s.getBoolean("settings.bungeecord", false)) {
            boolean guarded = reg != null && reg.has(PluginRegistry.Category.PROXY_AUTH);
            add(l, "bungeecord-mode", "core", guarded ? Severity.MEDIUM : Severity.HIGH,
                    "BungeeCord mode trusts the proxy",
                    "settings.bungeecord=true makes the server trust the player identity sent by the proxy. If the server port is reachable directly, attackers can bypass the proxy and spoof ANY player/UUID, including admins."
                            + (guarded ? " (BungeeGuard is installed, which adds a forwarding token - keep its secret set and the port firewalled.)" : ""),
                    "Firewall the server port so only the proxy can reach it, and use modern forwarding (Velocity) or BungeeGuard. Disable bungeecord if this isn't a network server.");
        }
        if (s.getInt("settings.timeout-time", 60) <= 0) {
            add(l, "watchdog-off", "reliability", Severity.LOW,
                    "Server watchdog effectively off",
                    "spigot.yml timeout-time is non-positive, so the watchdog won't restart a frozen server.",
                    "Leave timeout-time at a sane value (e.g. 60) so a hung server recovers on its own.");
        }
    }

    private void checkPaper(List<Finding> l) {
        YamlConfiguration p = env.yaml("config/paper-global.yml", "paper-global.yml", "paper.yml");
        if (p == null) {
            return;
        }
        // Velocity modern forwarding without a secret - check both the modern (paper-global.yml)
        // and legacy (paper.yml) layouts.
        boolean velocityModern = p.getBoolean("proxies.velocity.enabled", false);
        boolean velocityLegacy = p.getBoolean("settings.velocity-support.enabled", false);
        if (velocityModern || velocityLegacy) {
            String secret = velocityModern
                    ? p.getString("proxies.velocity.secret", "")
                    : p.getString("settings.velocity-support.secret", "");
            if (secret == null || secret.isEmpty()) {
                add(l, "velocity-no-secret", "core", Severity.HIGH,
                        "Velocity forwarding without a secret",
                        "Velocity modern forwarding is on but the secret is empty, so the backend can't verify the proxy - players can be spoofed.",
                        "Set the same forwarding secret in the proxy and in the server's Velocity secret.");
            }
        }
        if (p.getBoolean("console.has-all-permissions", false)) {
            add(l, "console-all-permissions", "core", Severity.MEDIUM,
                    "Console has all permissions",
                    "console.has-all-permissions=true gives the console (and any plugin that runs commands as the console) every permission, bypassing plugin permission checks. If a plugin routes untrusted input to the console, that's a privilege-escalation path.",
                    "Set console.has-all-permissions=false so the console respects plugin permissions.");
        }

        boolean usernameValidation = p.getBoolean("unsupported-settings.perform-username-validation",
                p.getBoolean("settings.unsupported-settings.perform-username-validation", true));
        if (!usernameValidation) {
            add(l, "bad-username-validation", "core", Severity.HIGH,
                    "Username validation disabled",
                    "perform-username-validation=false lets players join with names containing unusual characters. That can break per-name data and be abused to spoof or inject via usernames in commands/logs.",
                    "Set perform-username-validation back to true.");
        }

        ConfigurationSection unsupported = p.getConfigurationSection("unsupported-settings");
        if (unsupported == null) {
            unsupported = p.getConfigurationSection("settings.unsupported-settings");
        }
        if (unsupported != null) {
            for (String key : unsupported.getKeys(false)) {
                String low = key.toLowerCase();
                if ((low.contains("exploit") || low.contains("dupe") || low.contains("duplication"))
                        && unsupported.getBoolean(key, false)) {
                    add(l, "unsupported-exploit", "world", Severity.MEDIUM,
                            "Dangerous 'unsupported' setting enabled",
                            "Paper's unsupported-settings.{0} is true, which intentionally re-enables a known exploit or dupe.",
                            "Set {0} back to false unless you fully understand the consequence.", key);
                    break;
                }
            }
        }
    }

    private void checkBukkit(Properties props, List<Finding> l) {
        YamlConfiguration b = env.yaml("bukkit.yml");
        if (b == null) {
            return;
        }
        // Only relevant when the query protocol is actually serving requests.
        if (b.getBoolean("settings.query-plugins", true) && equals(props, "enable-query", "true")) {
            add(l, "query-plugins", "core", Severity.LOW,
                    "Query exposes the full plugin list",
                    "bukkit.yml settings.query-plugins=true makes the (enabled) query protocol hand out your exact plugin list and versions, which attackers use to fingerprint known-vulnerable plugins on your server.",
                    "Set query-plugins=false in bukkit.yml, or turn the query protocol off entirely with enable-query=false in server.properties.");
        }
        int throttle = b.getInt("settings.connection-throttle", 4000);
        if (throttle <= 0 && connectionThrottleNeedsAdvisory(throttle, behindProxy())) {
            add(l, "connection-throttle-off", "reliability", Severity.LOW,
                    "Connection throttle is disabled",
                    "bukkit.yml settings.connection-throttle={0} disables Bukkit's per-IP reconnect delay. On a standalone server that makes join-floods cheaper; Bulwark suppresses this finding when proxy forwarding is configured because proxy backends often disable it deliberately.",
                    "Set settings.connection-throttle to a positive value such as 4000 unless this server is a backend behind a correctly firewalled proxy.",
                    throttle);
        }
    }

    private void checkCommandSurface(List<Finding> l) {
        CommandSurface.Result surface = new CommandSurface(plugin).scan();
        if (!surface.available || surface.partial) {
            add(l, "command-surface-unavailable", "reliability", Severity.INFO,
                    "Command surface could not be read",
                    "Bulwark could not read the live command map on this platform ({0}). This does not lower the grade, but it means command exposure checks were skipped or limited to plugin.yml metadata rather than treated as clean.",
                    "Check the server console for platform-specific errors. If this is a hybrid or custom fork, keep command exposure reviewed manually.", surface.failure);
        }
        if (!surface.available) {
            return;
        }

        List<CommandSurface.Entry> disclosure = surface.publicDisclosure();
        if (!disclosure.isEmpty()) {
            add(l, "command-disclosure-public", "core", Severity.LOW,
                    "Public command metadata is visible",
                    "Commands such as {0} are declared as public or default-everyone. They can reveal server software or plugin names to anyone who can run them.",
                    "If you do not want public fingerprinting, restrict these command permissions or disable public plugin/version commands in your permission setup.",
                    CommandSurface.examples(disclosure, 5));
        }

        List<CommandSurface.Entry> namespaceOp = surface.namespaceOpReachable();
        if (!namespaceOp.isEmpty()) {
            add(l, "command-namespace-op-reachable", "access", Severity.INFO,
                    "Namespaced operator commands are visible",
                    "Bulwark found namespaced operator command labels such as {0}. This does not mean players can run them; it means any future command blocker or allowlist must handle namespaces too.",
                    "Make sure command policies match exact labels and namespaces, not only bare aliases like /op.",
                    CommandSurface.examples(namespaceOp, 5));
        }

        List<CommandSurface.Duplicate> duplicates = surface.riskyDuplicates();
        if (!duplicates.isEmpty()) {
            add(l, "command-shadowed-alias", "access", Severity.INFO,
                    "Sensitive command labels are shadowed",
                    "Multiple command owners expose the same sensitive label(s): {0}. This can confuse staff and can bypass naive command filters that only check one owner.",
                    "Review these duplicates and use exact namespaced command policies where needed.",
                    CommandSurface.duplicateExamples(duplicates, 6));
        }

        List<CommandSurface.Entry> pluginManagers = surface.pluginManagerCommands();
        if (!pluginManagers.isEmpty()) {
            add(l, "command-plugin-manager-risk", "plugins", anyPublic(pluginManagers) ? Severity.MEDIUM : Severity.LOW,
                    "Plugin-manager commands are installed",
                    "Bulwark found plugin-manager command labels such as {0}. These tools are useful for admins, but if exposed they can unload/reload plugins and widen incident impact.",
                    "Keep plugin-manager commands restricted to trusted operators, or remove the plugin from production servers if you only use it for testing.",
                    CommandSurface.examples(pluginManagers, 5));
        }

        List<CommandSurface.Entry> dangerousDefaults = surface.dangerousDefaults();
        if (!dangerousDefaults.isEmpty()) {
            add(l, "command-dangerous-default-permission", "access", Severity.LOW,
                    "Risky commands have public-looking defaults",
                    "These command labels declare no Bukkit permission or a default-everyone permission: {0}. This is metadata only; Bulwark is not claiming any specific player can run them.",
                    "Give these commands explicit staff-only permissions in your permissions plugin and test with a non-staff account.",
                    CommandSurface.examples(dangerousDefaults, 6));
        }

        List<CommandSurface.Entry> lifecycle = surface.lifecycleExposed();
        if (!lifecycle.isEmpty()) {
            add(l, "command-lifecycle-exposed", "access", Severity.LOW,
                    "Lifecycle commands have public-looking defaults",
                    "Lifecycle command labels such as {0} declare no Bukkit permission or a default-everyone permission. These labels should never be reachable by normal players.",
                    "Restrict lifecycle commands to trusted operators and prefer console-only operational workflows.",
                    CommandSurface.examples(lifecycle, 6));
        }

        String permissionNodes = permissionSummary(surface.riskyEntries(), 8);
        if (!permissionNodes.isEmpty()) {
            add(l, "permission-summary", "advisory-tools", Severity.INFO,
                    "Sensitive command permission nodes found",
                    "Bulwark found raw permission nodes declared on sensitive command metadata: {0}. This is informational only; it does not prove any player or group currently has those permissions.",
                    "Review these nodes in your permissions plugin and test the effective permissions with a non-staff account.",
                    permissionNodes);
        }

        List<CommandSurface.Entry> tabTargets = surface.tabCompleteTargets();
        if (tabCompleteLikelyEnabled() && !tabTargets.isEmpty()) {
            add(l, "command-tabcomplete-disclosure", "core", Severity.INFO,
                    "Tab-complete can reveal sensitive command names",
                    "Sensitive command labels exist in the command map ({0}). If tab-complete is open to players, those names can be disclosed even when execution is still permission-protected.",
                    "If command secrecy matters on this server, restrict tab-complete suggestions with your platform/permissions setup.",
                    CommandSurface.examples(tabTargets, 6));
        }
    }

    private void checkRuntime(List<Finding> l) {
        int major = parseJavaMajor(System.getProperty("java.version", ""));
        if (major > 0 && major < 17) {
            Severity sev = major < 11 ? Severity.MEDIUM : Severity.LOW;
            add(l, "old-java", "runtime", sev,
                    "Outdated Java ({0})",
                    "You're on Java {1}. Older Java misses security patches and performance work; modern Minecraft (1.18+) needs Java 17+.",
                    "Update to a current LTS Java (17 or 21) that matches your Minecraft version.",
                    System.getProperty("java.version", "?"), major);
        }

        String mc = mcVersion();
        if (mc != null) {
            int[] v = parseVersion(mc);
            if (v != null && isBefore(v, new int[]{1, 18, 1}) && !hasLog4jMitigation()) {
                add(l, "log4shell", "runtime", Severity.MEDIUM,
                        "Minecraft version from the Log4Shell era",
                        "Detected Minecraft {0}, from the period affected by CVE-2021-44228 (Log4Shell). Whether you're actually exposed depends on your build: Paper/Spigot jars from 2021-12-10 or later embed patched Log4j (2.15+) and are safe.",
                        "Make sure your server jar is a build from 2021-12-10 or later (or update to 1.18.1+), or launch with -Dlog4j2.formatMsgNoLookups=true.", mc);
            }
        }
    }

    private void checkDuplicatePlugins(List<Finding> l) {
        File dir = env.pluginsDir();
        File[] jars = dir.listFiles(new FilenameFilter() {
            public boolean accept(File d, String name) {
                return name.toLowerCase().endsWith(".jar");
            }
        });
        if (jars == null) {
            return;
        }
        Map<String, Integer> counts = new HashMap<>();
        for (File jar : jars) {
            String name = ServerEnv.pluginName(jar);
            if (name != null) {
                counts.merge(name.toLowerCase(), 1, Integer::sum);
            }
        }
        List<String> dups = new ArrayList<>();
        for (Map.Entry<String, Integer> e : counts.entrySet()) {
            if (e.getValue() > 1) {
                dups.add(e.getKey());
            }
        }
        if (!dups.isEmpty()) {
            add(l, "duplicate-plugins", "plugins", Severity.LOW,
                    "Duplicate plugin jars ({0})",
                    "More than one jar declares the same plugin: {1}. Duplicate or old copies cause conflicts, the wrong version loading, and hard-to-trace bugs.",
                    "Keep a single, up-to-date jar per plugin in /plugins and delete the extras.", dups.size(), String.join(", ", dups));
        }
    }

    private void checkPluginTrust(List<Finding> l) {
        PluginTrust trust = new PluginTrust(plugin, env);
        if (!trust.hasBaseline()) {
            return;
        }
        List<PluginTrust.Delta> delta = trust.diff();
        if (delta.isEmpty()) {
            return;
        }
        int hard = 0;
        for (PluginTrust.Delta d : delta) {
            if (!"new".equals(d.type)) {
                hard++;
            }
        }
        add(l, "plugin-trust-drift", "plugins", hard > 0 ? Severity.HIGH : Severity.MEDIUM,
                "Plugin jars changed since the trusted baseline",
                "{0} plugin jar change(s) were detected since the trusted baseline: {1}. A changed, missing or unexpected jar can mean a bad update, a leftover copy or tampering.",
                "If this was intentional, verify the download source and run /bulwark trust baseline. Otherwise remove the unknown jar and restore the expected one from a clean backup.",
                delta.size(), trustSummary(delta));
    }

    private void checkInventory(Properties props, List<Finding> l) {
        MinecraftInventory.Result inv = new MinecraftInventory(plugin, env).scan();
        List<String> misplaced = new ArrayList<>();
        List<String> unknown = new ArrayList<>();
        List<String> rootLoadable = new ArrayList<>();
        List<String> badPacks = new ArrayList<>();
        List<String> writable = new ArrayList<>();
        int mods = 0;
        for (MinecraftInventory.Item i : inv.items) {
            if ("mod".equals(i.type) || "hybrid".equals(i.type)) {
                mods++;
            }
            if (i.flags.contains("mod metadata in plugins/")
                    || i.flags.contains("plugin metadata in mods/")
                    || i.flags.contains("proxy plugin in Bukkit plugins/")) {
                misplaced.add(i.path);
            }
            if (i.flags.contains("no known Minecraft plugin metadata")
                    || i.flags.contains("no known Minecraft mod metadata")) {
                unknown.add(i.path);
            }
            if (i.flags.contains("loadable metadata outside plugins/ or mods/")) {
                rootLoadable.add(i.path);
            }
            if (i.flags.contains("missing pack.mcmeta")) {
                badPacks.add(i.path);
            }
            if (i.flags.contains("world-writable") && !i.path.startsWith("plugins/")) {
                writable.add(i.path);
            }
        }
        if (mods > 0 && profile.moddedRuntime()) {
            add(l, "artifact-mods-present", "plugins", Severity.INFO,
                    "Mod loader surface detected",
                    "Bulwark found {0} mod jar(s). Mods run as JVM code and usually bypass Bukkit's permission model, so plugin checks do not cover their full attack surface.",
                    "Keep mods from trusted sources only, update them with the server, and review them separately from Bukkit/Paper plugins.", mods);
        } else if (mods > 0) {
            add(l, "artifact-mods-without-loader", "plugins", Severity.INFO,
                    "Mod jars found without a confirmed mod loader",
                    "Bulwark found {0} mod jar(s), but the runtime did not confirm Forge, NeoForge, Fabric, Quilt or a Bukkit/mod hybrid. This is often a leftover folder, a server-pack copy, or a loader mismatch.",
                    "Remove stale mod jars, or verify the intended loader and version before treating those mods as active.", mods);
        }
        if (!misplaced.isEmpty()) {
            add(l, "artifact-misplaced-jar", "plugins", Severity.MEDIUM,
                    "Plugin/mod jars appear to be in the wrong loader folder",
                    "These jar(s) expose metadata for a different loader or proxy: {0}. Misplaced jars cause failed loads, old copies staying around, or the wrong server component receiving code it should not load.",
                    "Move each jar to the correct server/proxy/mods folder, or remove it if it is a leftover copy.", summary(misplaced));
        }
        if (!unknown.isEmpty()) {
            add(l, "artifact-unknown-jar", "plugins", Severity.LOW,
                    "Jar files without known Minecraft metadata",
                    "These jar(s) in loadable folders do not expose recognized plugin/mod metadata: {0}. They may be leftovers, shaded libraries, broken downloads or jars for another loader.",
                    "Remove unknown jars from plugins/ and mods/ unless you can prove they are required by your loader.", summary(unknown));
        }
        if (!rootLoadable.isEmpty()) {
            add(l, "artifact-root-loadable-jar", "plugins", Severity.LOW,
                    "Plugin/mod jars are sitting in the server root",
                    "These jar(s) contain plugin or mod metadata but are outside plugins/ or mods/: {0}. They are probably leftovers or misplaced artifacts.",
                    "Keep the server root clean: put loadable jars in the correct folder and remove old copies.", summary(rootLoadable));
        }
        if (!badPacks.isEmpty()) {
            add(l, "artifact-invalid-datapack", "world", Severity.LOW,
                    "Datapacks with missing metadata",
                    "These datapack entries are missing pack.mcmeta or could not be read: {0}. Broken datapacks can silently fail, hide stale code, or make function behaviour harder to audit.",
                    "Remove broken datapack folders/zips or replace them with a valid pack that includes pack.mcmeta.", summary(badPacks));
        }
        int fpl = intValue(props, "function-permission-level", 2);
        if (fpl > 2 && inv.functions() > 0) {
            add(l, "artifact-datapack-functions-elevated", "access", Severity.MEDIUM,
                    "Datapack functions can run with elevated permissions",
                    "Bulwark found {0} .mcfunction file(s), and function-permission-level is {1}. That gives datapack code stronger command privileges than most servers need.",
                    "Set function-permission-level back to 2 unless every datapack function is trusted and needs elevated command access.", inv.functions(), fpl);
        }
        if (!writable.isEmpty()) {
            add(l, "artifact-writable-loadable", "host", Severity.HIGH,
                    "Loadable Minecraft artifacts are world-writable",
                    "These loadable files or folders can be modified by other OS users: {0}. That is a local supply-chain path into the server process.",
                    "Tighten file ownership and permissions so only the Minecraft server user can write to mods, datapacks, root jars and startup files.", summary(writable));
        }
    }

    /**
     * Operating-system file-permission checks - hardening of the HOST, which no other Minecraft
     * plugin audits. Skips cleanly on filesystems without POSIX permissions (e.g. Windows).
     */
    private void checkFilePermissions(List<Finding> l) {
        // On a panel/container the server runs isolated as a single user, so host-level file
        // permissions matter far less - report them as awareness (INFO) rather than a real risk.
        boolean managed = profile.managedHosting();
        String managedNote = managed
                ? Messages.t("note.managed", " (You're on {0}, where the server is isolated, so this matters less than on a shared host.)", profile.hosting)
                : "";

        File sp = env.file("server.properties");
        Boolean spReadable = env.othersCanRead(sp);
        if (spReadable != null && spReadable && !env.prop("rcon.password").isEmpty()) {
            add(l, "host-readable-secret", "host", managed ? Severity.INFO : Severity.MEDIUM,
                    "server.properties is world-readable and holds an RCON password",
                    "server.properties can be read by any other user account on this machine, and it contains your RCON password in plain text - so any local user (or a compromised plugin running as another user) can read it.{0}",
                    "Restrict it so only the server's own user can read it (e.g. chmod 600 server.properties).", managedNote);
        }

        File pluginsDir = env.pluginsDir();
        Boolean dirWritable = env.othersCanWrite(pluginsDir);
        boolean jarWritable = false;
        File[] jars = pluginsDir.listFiles(new FilenameFilter() {
            public boolean accept(File d, String name) {
                return name.toLowerCase().endsWith(".jar");
            }
        });
        if (jars != null) {
            for (File jar : jars) {
                Boolean w = env.othersCanWrite(jar);
                if (w != null && w) {
                    jarWritable = true;
                    break;
                }
            }
        }
        if ((dirWritable != null && dirWritable) || jarWritable) {
            add(l, "host-writable-plugins", "host", managed ? Severity.INFO : Severity.HIGH,
                    "Plugin jars are world-writable",
                    "The plugins folder or its jars can be written by other OS users, so anyone with a shell on this host could replace a plugin with a backdoored one - a local supply-chain attack.{0}",
                    "Tighten ownership/permissions so only the server user can write to plugins/ (e.g. chown to the server user and chmod 750).", managedNote);
        }
    }

    /**
     * Host/system checks (run as part of a consented scan): the OS user the server runs as, the writability of the
     * server directory, exposure of ops.json, and the JVM heap vs. machine RAM. All read-only.
     */
    private void checkSystem(List<Finding> l) {
        boolean managed = profile.managedHosting();
        String managedNote = managed
                ? Messages.t("note.managed", " (You're on {0}, where the server is isolated, so this matters less than on a shared host.)", profile.hosting)
                : "";

        if (env.runningAsRoot()) {
            add(l, "process-as-root", "host", managed ? Severity.INFO : Severity.HIGH,
                    "Server process is running as root",
                    "The Minecraft server runs as the root user. Any plugin - or a remote-code-execution bug in one - then controls the whole machine, not just the server. That's the worst possible blast radius for a compromise.{0}",
                    "Run the server as a dedicated non-root user: create one, chown the server files to it, and start the service as that user.", managedNote);
        }

        Boolean rootWritable = env.othersCanWrite(env.root());
        if (rootWritable != null && rootWritable) {
            add(l, "host-writable-root", "host", managed ? Severity.INFO : Severity.HIGH,
                    "The server directory is world-writable",
                    "The server's working directory can be written by other OS users, so anyone with a shell on this host could drop or replace files the server loads - configs, jars, start scripts - a local supply-chain attack.{0}",
                    "Tighten it so only the server user can write: chown the directory to the server user and chmod it to 750.", managedNote);
        }

        File ops = env.file("ops.json");
        Boolean opsReadable = env.othersCanRead(ops);
        if (ops.isFile() && opsReadable != null && opsReadable) {
            add(l, "host-readable-ops", "host", managed ? Severity.INFO : Severity.LOW,
                    "ops.json is world-readable",
                    "ops.json - the list of operator accounts and their UUIDs - can be read by any other user on this machine, handing an attacker a ready-made list of the highest-value accounts to target.{0}",
                    "Restrict it so only the server user can read it (e.g. chmod 600 ops.json).", managedNote);
        }

        long xmx = env.maxHeapBytes();
        long ram = env.physicalRamBytes();
        if (xmx > 0 && ram > 0 && xmx > ram * 9 / 10) {
            add(l, "jvm-heap", "reliability", Severity.LOW,
                    "JVM heap is nearly all of system RAM",
                    "The JVM max heap (-Xmx ~{0} MB) is {1}% of the machine's RAM (~{2} MB). That leaves almost nothing for the OS, off-heap memory and other processes, so the server risks being OOM-killed or swapping itself to a crawl.",
                    "Leave headroom: set -Xmx to roughly 70-80% of RAM (and Xms equal to Xmx), accounting for anything else running on the box.", (xmx >> 20), (xmx * 100 / ram), (ram >> 20));
        }
    }

    /**
     * Context-aware checks driven by the detected environment: a note for Forge hybrids, and
     * honest "you might be missing X" recommendations (INFO - never lower the grade). These turn
     * other security tools into recommendations instead of pretending Bulwark replaces them.
     */
    private void checkContext(List<Finding> l) {
        if (profile.moddedRuntime()) {
            add(l, "forge-mod-surface", "plugins", Severity.INFO,
                    "Mods run outside this audit",
                    "This server is running {0}. Mods run with full JVM access and don't go through Bukkit's permission system, so Bulwark's grade only covers the Bukkit/plugin layer - not the mods.",
                    "Audit your mods separately and only run mods you trust.", profile.loaderLine());
        }
        if (profile.moddedRuntime()) {
            if (!reg.has(PluginRegistry.Category.ANTICHEAT)) {
                add(l, "loader-anticheat-context", "advisory-tools", Severity.INFO,
                        "No loader-compatible anti-cheat verified",
                        "Bulwark detected {0}. Generic Bukkit anti-cheat recommendations may not fit modded/hybrid servers, so this is reported as loader context instead of a normal missing-plugin recommendation.",
                        "Use an anti-cheat or moderation stack tested with this exact loader and Minecraft version.", profile.loaderLine());
            }
        } else {
            gap(l, PluginRegistry.Category.ANTICHEAT, "gap-no-anticheat",
                    "No anti-cheat detected",
                    "Bulwark audits configuration, not gameplay cheating. No anti-cheat plugin was found.",
                    "Consider Grim (free) or Vulcan if players can cheat on this server.");
        }
        gap(l, PluginRegistry.Category.LOGGING, "gap-no-logging",
                "No change logger detected",
                "No block/inventory logger was found, so you can't roll back or trace grief and theft after the fact.",
                "Consider CoreProtect (free) for forensic rollback.");
        if (backupReadinessMissing(reg)) {
            add(l, "backup-readiness", "advisory-tools", Severity.INFO,
                    "No backup evidence found in plugins",
                    "Bulwark did not find a known backup plugin. This is only a local plugin check; you may still have host snapshots, panel backups or cron jobs outside the server.",
                    "Keep regular off-site backups and periodically test a restore. If backups are handled outside Minecraft, document that outside the plugin list.");
        }
    }

    /** Adds an INFO recommendation only if no plugin in that category is installed. */
    private void gap(List<Finding> l, PluginRegistry.Category cat, String id, String title, String detail, String fix) {
        if (!reg.has(cat)) {
            add(l, id, "advisory-tools", Severity.INFO, title, detail, fix);
        }
    }

    // ---------- helpers ----------

    private static String trustSummary(List<PluginTrust.Delta> delta) {
        List<String> parts = new ArrayList<>();
        int shown = 0;
        for (PluginTrust.Delta d : delta) {
            if (shown++ >= 6) {
                break;
            }
            parts.add(d.type + " " + d.name);
        }
        if (delta.size() > 6) {
            parts.add("+" + (delta.size() - 6) + " more");
        }
        return String.join(", ", parts);
    }

    private static String summary(List<String> values) {
        List<String> parts = new ArrayList<>();
        int shown = 0;
        for (String value : values) {
            if (shown++ >= 6) {
                break;
            }
            parts.add(value);
        }
        if (values.size() > 6) {
            parts.add("+" + (values.size() - 6) + " more");
        }
        return String.join(", ", parts);
    }

    private void checkAntiXrayPosture(List<Finding> l) {
        if (profile == null || !profile.paper) {
            return;
        }
        AntiXrayState state = paperAntiXrayState();
        String problem = antiXrayPostureProblem(state);
        if (problem.isEmpty()) {
            return;
        }
        add(l, "anti-xray-posture", "reliability", Severity.LOW,
                "Paper Anti-Xray posture needs review",
                "{0} reports {1}. This can expose ore placement to x-ray clients; Bulwark reports it as advisory because anti-xray can be a performance or gameplay tradeoff.",
                "If ore secrecy matters, enable Paper Anti-Xray and test engine-mode 2 for this Minecraft/Paper version. Otherwise document the reason and ignore this advisory.",
                state.source, problem);
    }

    private AntiXrayState paperAntiXrayState() {
        YamlConfiguration modern = env.yaml("config/paper-world-defaults.yml", "paper-world-defaults.yml");
        YamlConfiguration paper = env.yaml("paper.yml");
        YamlConfiguration world = env.yaml("world/paper-world.yml");
        return firstAntiXrayState(
                antiXrayState(modern, "paper-world-defaults.yml", "anticheat.anti-xray"),
                antiXrayState(paper, "paper.yml", "world-settings.default.anti-xray"),
                antiXrayState(paper, "paper.yml", "settings.anti-xray"),
                antiXrayState(world, "world/paper-world.yml", "anticheat.anti-xray"));
    }

    static AntiXrayState antiXrayState(YamlConfiguration yaml, String source, String basePath) {
        if (yaml == null || basePath == null || basePath.trim().isEmpty()) {
            return AntiXrayState.absent();
        }
        String enabledPath = basePath + ".enabled";
        String enginePath = basePath + ".engine-mode";
        boolean hasEnabled = yaml.contains(enabledPath);
        boolean hasEngine = yaml.contains(enginePath);
        if (!hasEnabled && !hasEngine) {
            return AntiXrayState.absent();
        }
        Boolean enabled = hasEnabled ? Boolean.valueOf(yaml.getBoolean(enabledPath, false)) : null;
        Integer engineMode = hasEngine ? Integer.valueOf(yaml.getInt(enginePath, 0)) : null;
        return new AntiXrayState(true, enabled, engineMode, source == null ? "" : source);
    }

    static String antiXrayPostureProblem(AntiXrayState state) {
        if (state == null || !state.present) {
            return "";
        }
        if (Boolean.FALSE.equals(state.enabled)) {
            return "anti-xray.enabled=false";
        }
        if (Boolean.TRUE.equals(state.enabled) && state.engineMode != null && state.engineMode.intValue() <= 1) {
            return "anti-xray.enabled=true with engine-mode=" + state.engineMode;
        }
        return "";
    }

    private static AntiXrayState firstAntiXrayState(AntiXrayState... states) {
        if (states != null) {
            for (AntiXrayState state : states) {
                if (state != null && state.present) {
                    return state;
                }
            }
        }
        return AntiXrayState.absent();
    }

    static boolean backupReadinessMissing(PluginRegistry registry) {
        return registry != null && !registry.has(PluginRegistry.Category.BACKUP);
    }

    static String permissionSummary(List<CommandSurface.Entry> entries, int max) {
        if (entries == null || entries.isEmpty() || max <= 0) {
            return "";
        }
        List<String> parts = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (CommandSurface.Entry e : entries) {
            if (e == null || !e.risky() || e.permission.isEmpty()) {
                continue;
            }
            String raw = e.permission + " (" + e.key + " / " + e.owner + ")";
            if (seen.add(raw) && parts.size() < max) {
                parts.add(raw);
            }
        }
        if (seen.size() > parts.size()) {
            parts.add("+" + (seen.size() - parts.size()) + " more");
        }
        return String.join(", ", parts);
    }

    private boolean behindProxy() {
        YamlConfiguration spigot = env.yaml("spigot.yml");
        if (spigot != null && spigot.getBoolean("settings.bungeecord", false)) {
            return true;
        }
        YamlConfiguration paper = env.yaml("config/paper-global.yml", "paper-global.yml", "paper.yml");
        if (paper != null) {
            if (paper.getBoolean("proxies.velocity.enabled", false)) {
                return true;
            }
            if (paper.getBoolean("settings.velocity-support.enabled", false)) {
                return true;
            }
        }
        return false;
    }

    private boolean tabCompleteLikelyEnabled() {
        YamlConfiguration spigot = env.yaml("spigot.yml");
        if (spigot == null) {
            return true;
        }
        return spigot.getInt("commands.tab-complete", 0) >= 0;
    }

    private static boolean anyPublic(List<CommandSurface.Entry> entries) {
        for (CommandSurface.Entry e : entries) {
            if (e.publicish()) {
                return true;
            }
        }
        return false;
    }

    private void checkFloodgatePosture(List<Finding> l) {
        boolean geyser = reg.installed("geyser-spigot") || reg.installed("geyser");
        boolean floodgate = reg.installed("floodgate");
        if (!geyser && !floodgate) {
            return;
        }
        File key = firstExisting("plugins/floodgate/key.pem", "plugins/Floodgate/key.pem",
                "plugins/Geyser-Spigot/key.pem", "plugins/Geyser/key.pem");
        if (key != null) {
            Boolean readable = env.othersCanRead(key);
            if (readable != null && readable) {
                add(l, "floodgate-key-readable", "host", profile.managedHosting() ? Severity.INFO : Severity.MEDIUM,
                        "Floodgate key is readable by other OS users",
                        "{0} can be read by other local users. Floodgate keys authenticate Bedrock identity forwarding, so leaked keys widen account-spoofing impact.",
                        "Restrict the key so only the Minecraft server user can read it, and rotate it if you suspect it was exposed.",
                        relative(key));
            }
            Boolean writable = env.othersCanWrite(key);
            if (writable != null && writable) {
                add(l, "floodgate-key-writable", "host", profile.managedHosting() ? Severity.INFO : Severity.HIGH,
                        "Floodgate key is writable by other OS users",
                        "{0} can be modified by other local users. A local user or compromised process could replace the forwarding key.",
                        "Restrict key ownership and permissions, then restart the proxy/backend components that use it.",
                        relative(key));
            }
        }
        YamlConfiguration geyserConfig = env.yaml("plugins/Geyser-Spigot/config.yml", "plugins/Geyser/config.yml",
                "plugins/Geyser-Bukkit/config.yml");
        String auth = geyserConfig == null ? "" : geyserConfig.getString("remote.auth-type", "");
        auth = auth == null ? "" : auth.trim().toLowerCase(Locale.ROOT);
        if (floodgate && !auth.isEmpty() && !"floodgate".equals(auth)) {
            add(l, "geyser-auth-type-mismatch", "core", Severity.LOW,
                    "Geyser auth-type does not match Floodgate",
                    "Floodgate is installed, but Geyser remote.auth-type is '{0}' instead of floodgate. That may force the wrong Bedrock authentication flow.",
                    "Set remote.auth-type to floodgate if this backend is meant to use Floodgate, or remove Floodgate if it is unused.",
                    auth);
        }
    }

    private File firstExisting(String... paths) {
        for (String path : paths) {
            File f = env.file(path);
            if (f.isFile()) {
                return f;
            }
        }
        return null;
    }

    private String relative(File file) {
        String root = env.root().getAbsoluteFile().toString();
        String path = file.getAbsoluteFile().toString();
        if (path.startsWith(root)) {
            path = path.substring(root.length());
            while (path.startsWith(File.separator)) {
                path = path.substring(1);
            }
        }
        return path.replace(File.separatorChar, '/');
    }

    private void add(List<Finding> l, String id, String cat, Severity sev, String title, String detail, String fix, Object... args) {
        String t = Messages.finding(id, "title", title, args);
        String d = Messages.finding(id, "detail", detail, args);
        String f = Messages.finding(id, "fix", fix, args);
        l.add(new Finding(id, cat, sev, t, d, f));
    }

    /** Applies a config severity-override for this finding's id, if one is set and valid. */
    private static Finding applyOverride(Finding f, ConfigurationSection overrides) {
        if (overrides == null) {
            return f;
        }
        String raw = overrides.getString(f.id);
        if (raw == null || raw.trim().isEmpty()) {
            return f;
        }
        try {
            Severity s = Severity.valueOf(raw.trim().toUpperCase());
            return new Finding(f.id, f.category, s, f.title, f.detail, f.fix, f.area);
        } catch (IllegalArgumentException ex) {
            return f; // unknown severity name - keep the default
        }
    }

    static final class AntiXrayState {
        final boolean present;
        final Boolean enabled;
        final Integer engineMode;
        final String source;

        AntiXrayState(boolean present, Boolean enabled, Integer engineMode, String source) {
            this.present = present;
            this.enabled = enabled;
            this.engineMode = engineMode;
            this.source = source == null ? "" : source;
        }

        static AntiXrayState absent() {
            return new AntiXrayState(false, null, null, "");
        }
    }

    static boolean equals(Properties p, String key, String expected) {
        return expected.equalsIgnoreCase(p.getProperty(key, "").trim());
    }

    static String value(Properties p, String key) {
        return p.getProperty(key, "").trim();
    }

    static int intValue(Properties p, String key, int def) {
        try {
            return Integer.parseInt(p.getProperty(key, "").trim());
        } catch (Exception e) {
            return def;
        }
    }

    static boolean connectionThrottleNeedsAdvisory(int throttle, boolean behindProxy) {
        return throttle <= 0 && !behindProxy;
    }

    private String mcVersion() {
        try {
            String bv = plugin.getServer().getBukkitVersion(); // e.g. 1.20.1-R0.1-SNAPSHOT
            return bv == null ? null : bv.split("-")[0];
        } catch (Exception e) {
            return null;
        }
    }

    static int parseJavaMajor(String v) {
        try {
            if (v.startsWith("1.")) {
                return Integer.parseInt(v.split("\\.")[1]); // 1.8.0_x -> 8
            }
            int i = 0;
            while (i < v.length() && Character.isDigit(v.charAt(i))) {
                i++;
            }
            return Integer.parseInt(v.substring(0, i));
        } catch (Exception e) {
            return -1;
        }
    }

    static int[] parseVersion(String v) {
        try {
            String[] parts = v.split("\\.");
            int[] out = new int[]{0, 0, 0};
            for (int i = 0; i < parts.length && i < 3; i++) {
                out[i] = Integer.parseInt(parts[i].replaceAll("[^0-9]", ""));
            }
            return out;
        } catch (Exception e) {
            return null;
        }
    }

    static boolean isBefore(int[] a, int[] b) {
        for (int i = 0; i < 3; i++) {
            if (a[i] < b[i]) {
                return true;
            }
            if (a[i] > b[i]) {
                return false;
            }
        }
        return false;
    }

    /** True if the server was launched with the Log4Shell mitigation flag. */
    private static boolean hasLog4jMitigation() {
        try {
            for (String arg : java.lang.management.ManagementFactory.getRuntimeMXBean().getInputArguments()) {
                if (arg.toLowerCase().contains("formatmsgnolookups=true")) {
                    return true;
                }
            }
        } catch (Exception ignored) {
            // can't read JVM args - assume not mitigated and let the heuristic stand
        }
        return false;
    }
}
