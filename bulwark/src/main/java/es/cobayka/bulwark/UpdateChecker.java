package es.cobayka.bulwark;

import org.bukkit.plugin.java.JavaPlugin;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Checks whether a newer version of Bulwark exists and NOTIFIES - it never downloads or replaces the
 * jar. Auto-updating a jar from a URL is precisely the supply-chain risk Bulwark audits for (a
 * world-writable jar getting swapped), and for the paid tiers it would also fight the marketplace's
 * purchase/licence model. So this only tells you; you download the update yourself.
 *
 * The version source is a URL the admin points at their resource's version endpoint (SpigotMC's
 * update.php returns the bare version; a JSON body with a "version" field also works). Blank = off.
 * Fails OPEN: any network/parse error is swallowed, never logged as a problem.
 */
final class UpdateChecker {

    /** Optional extra notification (webhook) for tiers that have one; the console notice is always sent. */
    interface Notifier {
        void onUpdate(String latest, String current);
    }

    private static final Pattern VERSION = Pattern.compile("^(\\d+(?:\\.\\d+)*)");
    private static final Pattern JSON_VERSION = Pattern.compile("\"version\"\\s*:\\s*\"([^\"]+)\"");

    private final JavaPlugin plugin;
    private final Notifier notifier;
    private volatile String latest;
    private volatile boolean outdated;
    private volatile String notifiedVersion;
    private ScheduledExecutorService exec;

    UpdateChecker(JavaPlugin plugin, Notifier notifier) {
        this.plugin = plugin;
        this.notifier = notifier;
    }

    void start() {
        if (!plugin.getConfig().getBoolean("updates.check", true)) {
            return;
        }
        Thread t = new Thread(this::check, "Bulwark-Update-Init");
        t.setDaemon(true);
        t.start();
        long hours = Math.max(1, plugin.getConfig().getLong("updates.interval-hours", 24));
        exec = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread h = new Thread(r, "Bulwark-Update");
            h.setDaemon(true);
            return h;
        });
        exec.scheduleAtFixedRate(this::check, hours, hours, TimeUnit.HOURS);
    }

    void stop() {
        if (exec != null) {
            exec.shutdownNow();
            exec = null;
        }
    }

    boolean outdated() {
        return outdated;
    }

    String latest() {
        return latest;
    }

    private void check() {
        String url = plugin.getConfig().getString("updates.url", "").trim();
        if (url.isEmpty()) {
            return; // no version source configured (the default until the resource is published)
        }
        try {
            String v = parseVersion(httpGet(url));
            if (v.isEmpty()) {
                return;
            }
            String cur = plugin.getDescription().getVersion();
            if (isNewer(v, cur)) {
                latest = v;
                outdated = true;
                if (shouldNotify(v, notifiedVersion)) {
                    notifiedVersion = v;
                    plugin.getLogger().warning("[updates] Bulwark " + v + " is available (you're on " + cur
                            + "). Download it from your resource page - Bulwark never auto-downloads itself.");
                    if (notifier != null) {
                        try {
                            notifier.onUpdate(v, cur);
                        } catch (Throwable ignored) {
                            // a notifier failure must not break the check
                        }
                    }
                }
            } else {
                outdated = false;
            }
        } catch (Exception networkOrParse) {
            // fail OPEN - an update check is best-effort, never a problem to report
        }
    }

    static boolean shouldNotify(String latest, String notifiedVersion) {
        return latest != null && !latest.equals(notifiedVersion);
    }

    private String httpGet(String url) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestMethod("GET");
        c.setRequestProperty("User-Agent", "Bulwark");
        c.setConnectTimeout(8000);
        c.setReadTimeout(8000);
        int code = c.getResponseCode();
        if (code >= 400) {
            c.disconnect();
            throw new java.io.IOException("HTTP " + code);
        }
        StringBuilder sb = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            int n = 0;
            while ((line = r.readLine()) != null && n++ < 200) {
                sb.append(line).append('\n');
            }
        }
        c.disconnect();
        return sb.toString();
    }

    /** Pulls a version out of the body: a JSON "version" field, else the first non-empty line. */
    private static String parseVersion(String body) {
        if (body == null) {
            return "";
        }
        Matcher m = JSON_VERSION.matcher(body);
        if (m.find()) {
            return m.group(1).trim();
        }
        for (String line : body.split("\n")) {
            String t = line.trim();
            if (!t.isEmpty()) {
                return t;
            }
        }
        return "";
    }

    /** True if dotted-numeric {@code latest} is greater than {@code current} (ignores -SNAPSHOT etc.). */
    static boolean isNewer(String latest, String current) {
        int[] a = parse(latest);
        int[] b = parse(current);
        int n = Math.max(a.length, b.length);
        for (int i = 0; i < n; i++) {
            int x = i < a.length ? a[i] : 0;
            int y = i < b.length ? b[i] : 0;
            if (x != y) {
                return x > y;
            }
        }
        return false;
    }

    private static int[] parse(String v) {
        if (v == null) {
            return new int[0];
        }
        String s = v.trim();
        if (s.toLowerCase(java.util.Locale.ROOT).startsWith("v")) {
            s = s.substring(1);
        }
        Matcher m = VERSION.matcher(s);
        if (!m.find()) {
            return new int[0];
        }
        String[] parts = m.group(1).split("\\.");
        int[] out = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            try {
                out[i] = Integer.parseInt(parts[i]);
            } catch (NumberFormatException e) {
                out[i] = 0;
            }
        }
        return out;
    }
}
