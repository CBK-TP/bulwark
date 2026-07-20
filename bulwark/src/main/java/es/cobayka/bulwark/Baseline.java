package es.cobayka.bulwark;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The Cobayka Hardening Baseline: a small, stable catalogue that gives every finding a citable
 * ID (CHB-xx) and groups it into a security area. There is no official CIS/industry benchmark for
 * Minecraft servers, so this is Cobayka's own reference - which is exactly what lets a Bulwark
 * report say "you're missing CHB-A1" and be quotable, shareable and recognisable.
 */
final class Baseline {

    /** Security areas, in the order reports show them. */
    static final List<String> AREAS = Arrays.asList(
            "Authentication", "Remote access", "Access control",
            "Proxy & forwarding", "Runtime", "Plugins", "World", "Host");

    /** Advisory area - shown separately, never affects the grade. */
    static final String HARDENING = "Hardening";
    static final String OTHER = "Other";

    private static final Map<String, String> CODE = new HashMap<>();
    private static final Map<String, String> AREA = new HashMap<>();

    private static void map(String id, String code, String area) {
        CODE.put(id, code);
        AREA.put(id, area);
    }

    static {
        // Authentication
        map("offline-mode", "CHB-A1", "Authentication");
        map("offline-mode-login", "CHB-A1", "Authentication");
        map("offline-mode-proxy", "CHB-A1", "Authentication");
        map("insecure-chat", "CHB-A2", "Authentication");
        map("bad-username-validation", "CHB-A3", "Authentication");
        map("resource-pack-no-sha", "CHB-A4", "Authentication");
        map("floodgate-online-mode", "CHB-A5", "Authentication");
        map("geyser-auth-type-mismatch", "CHB-A5", "Authentication");
        // Remote access
        map("rcon-no-password", "CHB-R1", "Remote access");
        map("rcon-weak-password", "CHB-R1", "Remote access");
        map("rcon-enabled", "CHB-R1", "Remote access");
        map("query-enabled", "CHB-R2", "Remote access");
        map("console-all-permissions", "CHB-R3", "Remote access");
        map("jmx-enabled", "CHB-R4", "Remote access");
        map("query-plugins", "CHB-R5", "Remote access");
        map("command-disclosure-public", "CHB-R5", "Remote access");
        map("command-tabcomplete-disclosure", "CHB-R5", "Remote access");
        map("accepts-transfers", "CHB-R6", "Remote access");
        // Access control
        map("no-whitelist", "CHB-C1", "Access control");
        map("whitelist-not-enforced", "CHB-C1", "Access control");
        map("many-operators", "CHB-C2", "Access control");
        map("high-op-permission-level", "CHB-C3", "Access control");
        map("command-blocks-enabled", "CHB-C4", "Access control");
        map("high-function-permission-level", "CHB-C5", "Access control");
        map("command-namespace-op-reachable", "CHB-C6", "Access control");
        map("command-shadowed-alias", "CHB-C6", "Access control");
        map("command-dangerous-default-permission", "CHB-C6", "Access control");
        map("command-lifecycle-exposed", "CHB-C6", "Access control");
        // Proxy & forwarding
        map("bungeecord-mode", "CHB-X1", "Proxy & forwarding");
        map("velocity-no-secret", "CHB-X2", "Proxy & forwarding");
        map("no-proxy-protection", "CHB-X3", "Proxy & forwarding");
        map("proxy-backend-firewall-unverified", "CHB-X4", "Proxy & forwarding");
        // Runtime
        map("old-java", "CHB-U1", "Runtime");
        map("log4shell", "CHB-U2", "Runtime");
        // Plugins
        map("duplicate-plugins", "CHB-G1", "Plugins");
        map("forge-mod-surface", "CHB-G2", "Plugins");
        map("plugin-trust-drift", "CHB-G3", "Plugins");
        map("artifact-mods-present", "CHB-G4", "Plugins");
        map("artifact-mods-without-loader", "CHB-G4", "Plugins");
        map("artifact-misplaced-jar", "CHB-G5", "Plugins");
        map("artifact-unknown-jar", "CHB-G6", "Plugins");
        map("artifact-root-loadable-jar", "CHB-G7", "Plugins");
        map("command-plugin-manager-risk", "CHB-G8", "Plugins");
        // World
        map("unsupported-exploit", "CHB-W1", "World");
        map("no-spawn-protection", "CHB-W2", "World");
        map("artifact-invalid-datapack", "CHB-W3", "World");
        map("anti-xray-off-public-survival", "CHB-W4", "World");
        map("artifact-datapack-functions-elevated", "CHB-C5", "Access control");
        // Host & system (operating-system hardening - unique to Bulwark; the deeper ones are
        // consent-gated, see system-scan in config.yml)
        map("host-readable-secret", "CHB-H1", "Host");
        map("host-writable-plugins", "CHB-H2", "Host");
        map("process-as-root", "CHB-H3", "Host");
        map("host-writable-root", "CHB-H4", "Host");
        map("host-readable-ops", "CHB-H5", "Host");
        map("artifact-writable-loadable", "CHB-H6", "Host");
        map("floodgate-key-readable", "CHB-H7", "Host");
        map("floodgate-key-writable", "CHB-H7", "Host");
        // Hardening (advisory; performance/reliability - excluded from the security grade)
        map("no-rate-limit", "CHB-D1", HARDENING);
        map("high-view-distance", "CHB-D2", HARDENING);
        map("high-simulation-distance", "CHB-D3", HARDENING);
        map("watchdog-off", "CHB-D4", HARDENING);
        map("watchdog-max-tick", "CHB-D5", HARDENING);
        map("jvm-heap", "CHB-D6", HARDENING);
        map("command-surface-unavailable", "CHB-D7", HARDENING);
        map("posture-profile-auto", "CHB-D8", HARDENING);
        map("posture-profile-invalid", "CHB-D8", HARDENING);
        map("posture-profile-unconfirmed", "CHB-D8", HARDENING);
        map("profile-private-whitelist-open", "CHB-C1", "Access control");
        map("loader-runtime-detected", "CHB-D8", HARDENING);
        map("loader-anticheat-context", "CHB-D8", HARDENING);
    }

    /** The CHB code for a finding id, or "" if it isn't catalogued. */
    static String code(String id) {
        String c = CODE.get(id);
        return c == null ? "" : c;
    }

    /** The security area for a finding id, or "Other" if the id isn't catalogued. */
    static String area(String id) {
        String a = AREA.get(id);
        return a == null ? OTHER : a;
    }

    private Baseline() {
    }
}
