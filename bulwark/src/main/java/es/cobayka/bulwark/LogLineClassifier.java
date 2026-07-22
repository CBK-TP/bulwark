package es.cobayka.bulwark;

import java.util.Optional;

final class LogLineClassifier {

    private static final int EXCEPTION_SCAN_LIMIT = 1024;

    private LogLineClassifier() {
    }

    static Optional<Finding> classify(String line) {
        if (line == null || line.isEmpty()) {
            return Optional.empty();
        }
        String low = line.toLowerCase(java.util.Locale.ROOT);
        if (low.contains("${jndi:")) {
            return Optional.of(f("log-jndi-probe", Severity.HIGH,
                    "Log4Shell-style lookup appeared in the log",
                    "A log line contains a literal ${jndi: lookup. Modern servers normally neutralize it, but it is still a high-confidence attack signal.",
                    "Confirm Java and server versions are supported, keep the mitigation flag on old 1.17-era servers, and review the source of the line."));
        }
        if (line.contains("A single server tick took")) {
            return Optional.of(f("log-watchdog-freeze", Severity.HIGH,
                    "Watchdog freeze was logged",
                    "The server logged a single tick taking too long. That usually means a hard stall, runaway plugin task or severe world load.",
                    "Inspect the timestamp around this line, capture a timings/spark profile, and review recent plugin or datapack changes."));
        }
        if (line.contains("--- DO NOT REPORT THIS TO PAPER")) {
            return Optional.of(f("log-paper-crash-report", Severity.HIGH,
                    "Paper crash banner found",
                    "Paper printed its crash-report banner. The log sample contains evidence of a server crash or fatal watchdog path.",
                    "Read the crash report referenced by Paper and review plugins mentioned immediately before the banner."));
        }
        if (line.contains("Can't keep up! Is the server overloaded?")) {
            return Optional.of(f("log-server-overloaded", Severity.MEDIUM,
                    "Server overload warning",
                    "Minecraft logged the standard can't-keep-up warning. It is a symptom of tick lag, overloaded hardware or heavy plugin/world work.",
                    "Correlate with player count and recent changes, then profile before changing random performance settings."));
        }
        if (line.contains("moved too quickly")) {
            return Optional.of(f("log-player-moved-too-quickly", Severity.LOW,
                    "Movement anomaly logged",
                    "The server logged moved-too-quickly. This is only a symptom; lag, teleport, elytra and plugins can trigger it.",
                    "Treat it as context for anti-cheat tuning, not as proof of cheating or a direct punishment trigger."));
        }
        if (line.contains("moved wrongly")) {
            return Optional.of(f("log-player-moved-wrongly", Severity.LOW,
                    "Movement correction logged",
                    "The server logged moved-wrongly. It can happen during lag, teleport, vehicle or collision edge cases.",
                    "Use it as an operational signal only; never act on it without live anti-cheat evidence."));
        }
        if (line.contains("Error occurred while enabling")) {
            return Optional.of(f("log-plugin-enable-error", Severity.HIGH,
                    "Plugin failed during enable",
                    "A plugin threw while enabling. That can leave protections partially loaded or silently missing.",
                    "Review the plugin named in the line, update it or remove it until it starts cleanly."));
        }
        if (line.contains("Could not load 'plugins/") || line.contains("Could not load plugin")) {
            return Optional.of(f("log-plugin-load-error", Severity.HIGH,
                    "Plugin jar failed to load",
                    "The server could not load a plugin jar. A broken security or dependency plugin may leave the server exposed.",
                    "Check the jar version, dependencies and Java/Minecraft compatibility, then restart after fixing it."));
        }
        if (line.contains("Could not pass event") || line.contains("generated an exception")) {
            return Optional.of(f("log-plugin-exception", Severity.MEDIUM,
                    "Plugin exception in log",
                    "A plugin exception was logged. One repeated stack can spam many lines, so Bulwark counts only matched signal lines.",
                    "Look at the plugin named around the exception and reproduce with latest plugin/server builds."));
        }
        if (line.contains("issued server command:")) {
            return Optional.of(f("log-command-issued", Severity.INFO,
                    "Command execution line",
                    "The sample contains command execution lines. This is normal, but useful when reviewing suspicious activity.",
                    "Review the command source in context and keep command logs protected because they can contain private staff actions."));
        }
        if (line.contains("lost connection: Failed to verify username") || line.contains("lost connection: Invalid session")) {
            return Optional.of(f("log-auth-failed", Severity.LOW,
                    "Authentication failure in log",
                    "The log contains failed login/session verification messages. Small amounts are normal; bursts can indicate bot traffic or account issues.",
                    "Correlate with connection rate and proxy settings before taking action."));
        }
        if (line.contains("Failed to load operators list")) {
            return Optional.of(f("log-operators-load-failed", Severity.MEDIUM,
                    "Operators list failed to load",
                    "The server could not load the operator list. Staff access state may not match what you expect.",
                    "Validate ops.json syntax and file permissions, then restart or reload carefully."));
        }
        if (line.contains("Failed to load white-list") || line.contains("Failed to load whitelist")) {
            return Optional.of(f("log-whitelist-load-failed", Severity.MEDIUM,
                    "Whitelist failed to load",
                    "The server could not load the whitelist. Access control may not match the intended private-server posture.",
                    "Validate whitelist.json syntax and file permissions, then confirm whitelist enforcement."));
        }
        if (looksLikeExceptionHeader(line)) {
            return Optional.of(f("log-plugin-exception", Severity.MEDIUM,
                    "Exception header in log",
                    "The sample contains an exception or error header. Bulwark reports the header rather than every stack frame.",
                    "Inspect the stack in latest.log and identify whether the first plugin frame belongs to a maintained plugin."));
        }
        return Optional.empty();
    }

    static Finding missingLatest(String reason) {
        String suffix = reason == null || reason.trim().isEmpty() ? "" : " (" + reason.trim() + ")";
        return f("log-file-missing", Severity.INFO,
                "latest.log could not be read",
                "Bulwark could not read logs/latest.log" + suffix + ". Log audit stays inactive and does not affect the security grade.",
                "Check that the server writes logs/latest.log and that the process user can read it.");
    }

    private static boolean looksLikeExceptionHeader(String line) {
        int limit = Math.min(line.length(), EXCEPTION_SCAN_LIMIT);
        for (int i = 0; i < limit; i++) {
            int suffix = exceptionSuffixAt(line, i, limit);
            if (suffix == 0) {
                continue;
            }
            int end = i + suffix;
            if (!exceptionDelimiter(line, end, limit)) {
                continue;
            }
            int start = i - 1;
            while (start >= 0 && (isJavaPart(line.charAt(start)) || line.charAt(start) == '.')) {
                start--;
            }
            start++;
            if (start < i && validQualifiedClassName(line, start, end)) {
                return true;
            }
        }
        return false;
    }

    private static int exceptionSuffixAt(String line, int start, int limit) {
        if (matchesAt(line, start, limit, "Exception")) {
            return "Exception".length();
        }
        if (matchesAt(line, start, limit, "Error")) {
            return "Error".length();
        }
        return 0;
    }

    private static boolean matchesAt(String line, int start, int limit, String needle) {
        if (start + needle.length() > limit) {
            return false;
        }
        for (int i = 0; i < needle.length(); i++) {
            if (line.charAt(start + i) != needle.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    private static boolean exceptionDelimiter(String line, int end, int limit) {
        if (end >= line.length()) {
            return true;
        }
        if (end >= limit) {
            return false;
        }
        char c = line.charAt(end);
        return c == ':' || Character.isWhitespace(c);
    }

    private static boolean validQualifiedClassName(String line, int start, int end) {
        boolean sawDot = false;
        boolean expectStart = true;
        boolean sawSegmentChar = false;
        for (int i = start; i < end; i++) {
            char c = line.charAt(i);
            if (c == '.') {
                if (expectStart || !sawSegmentChar) {
                    return false;
                }
                sawDot = true;
                expectStart = true;
                sawSegmentChar = false;
                continue;
            }
            if (expectStart) {
                if (!isJavaStart(c)) {
                    return false;
                }
                expectStart = false;
                sawSegmentChar = true;
                continue;
            }
            if (!isJavaPart(c)) {
                return false;
            }
            sawSegmentChar = true;
        }
        return sawDot && sawSegmentChar && !expectStart;
    }

    private static boolean isJavaStart(char c) {
        return c >= 'A' && c <= 'Z'
                || c >= 'a' && c <= 'z'
                || c == '_' || c == '$';
    }

    private static boolean isJavaPart(char c) {
        return isJavaStart(c) || c >= '0' && c <= '9';
    }

    private static Finding f(String id, Severity severity, String title, String detail, String fix) {
        return new Finding(id, "log", severity,
                Messages.finding(id, "title", title),
                Messages.finding(id, "detail", detail),
                Messages.finding(id, "fix", fix));
    }
}
