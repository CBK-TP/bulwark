package es.cobayka.bulwark;

import org.bukkit.plugin.java.JavaPlugin;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.StandardCopyOption;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class UpdateChecker {

    interface Notifier {
        void onUpdate(String latest, String current);
    }

    enum Mode {
        OFF, NOTIFY, DOWNLOAD
    }

    static final String KIND_PLUGIN = "bulwark-free";
    static final String KIND_RULES = "bulwark-rules";

    private static final String PUBLIC_KEY_PEM = "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAiRNCevvMq3IUcNBekZel\n"
            + "1bGowKB/PXdUYlul2qWJ98spmBv28xom6luKdO0IelEYtfL57wEqTx9Zhc6clILR\n"
            + "ngRU2ATqLXC1xMqbXfuoP4AS92rBacnuh/QRaL1hpwerj40rj8TaQGl2z9FmI8f/\n"
            + "+J4R23RqPyYq4n2D5+w0dlSE8dAR7u6HvliNnZ3Oq2JWfD6IVXFK04kM7RagzDKB\n"
            + "UTg1mPnszmNOc4Y3HTZ+Uld8IPXdlccn/u/JMX9AGeshBZIlLWVB7mZhHeLKlDQM\n"
            + "o0i+jwwqwpDekbX99A0i2ir5iEala5aNOU+TNheeXqZdORbZdRGnUp5FXhWJMZZW\n"
            + "KWP84+hLGSlTxq/liANZkQCIsqmRZMM40VmAoAGsOdhb5HuGrqVvukPCJp/sLMzQ\n"
            + "Y7VnoLcdofL86615xJiV35+ZDOV6x9/xpUSwT74tTVoocRUnoTTDp6JOAjhx7Iug\n"
            + "XQfP0td/Wi5A5mzohJ8xg1o0tzcpISRzStLwJAqdqv3bAgMBAAE=\n"
            + "-----END PUBLIC KEY-----";

    private static final Pattern VERSION = Pattern.compile("^(\\d+(?:\\.\\d+)*)");
    private static final Pattern JSON_VERSION = Pattern.compile("\"version\"\\s*:\\s*\"([^\"]+)\"");
    private static final int MAX_VERSION_BODY = 65536;
    private static final int MAX_MANIFEST_BODY = 65536;
    private static final int MAX_JAR_BYTES = 25 * 1024 * 1024;
    private static final int MAX_RULE_BYTES = 262144;
    private static final int MAX_DOWNLOAD_MILLIS = 20000;

    private final JavaPlugin plugin;
    private final Notifier notifier;
    private final boolean freeTier;
    private volatile String latest;
    private volatile boolean outdated;
    private volatile String notifiedVersion;
    private volatile String notifiedRulesVersion;
    private volatile boolean downloadDowngradeLogged;
    private ScheduledExecutorService exec;

    UpdateChecker(JavaPlugin plugin, Notifier notifier) {
        this(plugin, notifier, true);
    }

    UpdateChecker(JavaPlugin plugin, Notifier notifier, boolean freeTier) {
        this.plugin = plugin;
        this.notifier = notifier;
        this.freeTier = freeTier;
    }

    void start() {
        if (pluginMode() == Mode.OFF && rulesMode() == Mode.OFF) {
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
        try {
            checkPluginUpdate();
        } catch (Throwable ignored) {
        }
        try {
            checkRulesUpdate();
        } catch (Throwable ignored) {
        }
    }

    private void checkPluginUpdate() throws Exception {
        Mode requested = pluginMode();
        if (requested == Mode.OFF) {
            return;
        }
        String url = plugin.getConfig().getString("updates.url", "").trim();
        if (url.isEmpty()) {
            return;
        }
        String body = httpGet(url, MAX_VERSION_BODY, true);
        Manifest fromBody = Manifest.parse(body);
        String v = fromBody.version.isEmpty() ? parseVersion(body) : fromBody.version;
        if (v.isEmpty()) {
            return;
        }
        String cur = plugin.getDescription().getVersion();
        if (!isNewer(v, cur)) {
            outdated = false;
            return;
        }
        latest = v;
        outdated = true;
        if (shouldNotify(v, notifiedVersion)) {
            notifiedVersion = v;
            notifyUpdate(v, cur);
        }
        File updateDir = updateFolder();
        Mode effective = effectivePluginMode(requested, freeTier, updateDir != null);
        if (effective != Mode.DOWNLOAD) {
            logDownloadDowngrade(requested, effective);
            return;
        }
        Manifest manifest = fromBody.complete() ? fromBody : manifest(plugin.getConfig().getString("updates.manifest-url", "").trim());
        if (!manifest.complete() || !v.equals(manifest.version)) {
            return;
        }
        preparePluginDownload(manifest, updateDir);
    }

    private void checkRulesUpdate() throws Exception {
        Mode mode = rulesMode();
        if (mode == Mode.OFF) {
            return;
        }
        String url = plugin.getConfig().getString("rules.url", "").trim();
        if (url.isEmpty()) {
            return;
        }
        Manifest manifest = manifest(url);
        if (!manifest.complete() || !verifyManifest(publicKey(), KIND_RULES, manifest)) {
            return;
        }
        String current = CommunityRules.localVersion(plugin);
        if (!isNewer(manifest.version, current)) {
            return;
        }
        if (mode == Mode.NOTIFY) {
            if (shouldNotify(manifest.version, notifiedRulesVersion)) {
                notifiedRulesVersion = manifest.version;
                plugin.getLogger().info("[rules] Community rules update " + manifest.version + " is available.");
            }
            return;
        }
        byte[] bytes = downloadBytes(manifest.url, MAX_RULE_BYTES, true);
        if (!hashMatches(bytes, manifest.sha256) || !validRemoteRules(bytes)) {
            return;
        }
        writeRules(bytes, manifest.version);
    }

    private Mode pluginMode() {
        Object raw = plugin.getConfig().get("updates.mode");
        Boolean legacy = plugin.getConfig().contains("updates.check") ? plugin.getConfig().getBoolean("updates.check") : null;
        return mode(raw, legacy, Mode.NOTIFY);
    }

    private Mode rulesMode() {
        return mode(plugin.getConfig().get("rules.update"), null, Mode.OFF);
    }

    static Mode mode(Object raw, Boolean legacyCheck, Mode fallback) {
        if (raw instanceof Boolean) {
            return (Boolean) raw ? Mode.NOTIFY : Mode.OFF;
        }
        if (raw != null && !String.valueOf(raw).trim().isEmpty()) {
            String v = String.valueOf(raw).trim().toLowerCase(Locale.ROOT);
            if ("off".equals(v)) {
                return Mode.OFF;
            }
            if ("download".equals(v)) {
                return Mode.DOWNLOAD;
            }
            if ("notify".equals(v)) {
                return Mode.NOTIFY;
            }
        }
        if (legacyCheck != null) {
            return legacyCheck ? Mode.NOTIFY : Mode.OFF;
        }
        return fallback;
    }

    static Mode effectivePluginMode(Mode requested, boolean freeTier, boolean updateFolderAvailable) {
        if (requested != Mode.DOWNLOAD) {
            return requested;
        }
        return freeTier && updateFolderAvailable ? Mode.DOWNLOAD : Mode.NOTIFY;
    }

    private void notifyUpdate(String latest, String current) {
        plugin.getLogger().warning("[updates] Bulwark " + latest + " is available (you're on " + current + ").");
        if (notifier != null) {
            try {
                notifier.onUpdate(latest, current);
            } catch (Throwable ignored) {
            }
        }
    }

    private void logDownloadDowngrade(Mode requested, Mode effective) {
        if (requested != Mode.DOWNLOAD || effective == Mode.DOWNLOAD || downloadDowngradeLogged) {
            return;
        }
        downloadDowngradeLogged = true;
        plugin.getLogger().info("[updates] download mode is only available for Bulwark Free with a server update folder; using notify mode.");
    }

    private Manifest manifest(String url) throws Exception {
        if (url == null || url.trim().isEmpty()) {
            return Manifest.EMPTY;
        }
        return Manifest.parse(httpGet(url, MAX_MANIFEST_BODY, true));
    }

    private boolean preparePluginDownload(Manifest manifest, File updateDir) throws Exception {
        PublicKey key = publicKey();
        if (!verifyManifest(key, KIND_PLUGIN, manifest)) {
            plugin.getLogger().warning("[updates] Download manifest signature did not verify; keeping current jar.");
            return false;
        }
        byte[] jar = downloadBytes(manifest.url, MAX_JAR_BYTES, true);
        if (!hashMatches(jar, manifest.sha256)) {
            plugin.getLogger().warning("[updates] Downloaded jar hash mismatch; keeping current jar.");
            return false;
        }
        if (!updateDir.isDirectory() && !updateDir.mkdirs()) {
            return false;
        }
        if (!plugin.getDataFolder().isDirectory()) {
            plugin.getDataFolder().mkdirs();
        }
        File tmp = File.createTempFile("bulwark-update-", ".tmp", plugin.getDataFolder());
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write(jar);
        }
        try {
            File dest = destinationJar(updateDir, installedJar(), manifest.version);
            moveVerified(tmp, dest);
            plugin.getLogger().info("[updates] Bulwark " + manifest.version + " is prepared in the server update folder. Restart to apply it.");
            return true;
        } catch (Exception ex) {
            deleteQuietly(tmp);
            throw ex;
        }
    }

    private void writeRules(byte[] bytes, String version) throws Exception {
        if (!isNewer(version, CommunityRules.localVersion(plugin))) {
            return;
        }
        if (!plugin.getDataFolder().isDirectory()) {
            plugin.getDataFolder().mkdirs();
        }
        File tmp = File.createTempFile("community-rules-", ".tmp", plugin.getDataFolder());
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write(bytes);
        }
        try {
            File dest = new File(plugin.getDataFolder(), "community-rules.yml");
            moveVerified(tmp, dest);
            plugin.getLogger().info("[rules] Community rules " + version + " downloaded and verified.");
        } catch (Exception ex) {
            deleteQuietly(tmp);
            throw ex;
        }
    }

    private static void moveVerified(File tmp, File dest) throws Exception {
        try {
            Files.move(tmp.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException ex) {
            Files.move(tmp.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private File updateFolder() {
        try {
            Object f = plugin.getServer().getClass().getMethod("getUpdateFolderFile").invoke(plugin.getServer());
            return f instanceof File ? (File) f : null;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private File installedJar() {
        return plugin instanceof BulwarkPlugin ? ((BulwarkPlugin) plugin).installedJarFile() : null;
    }

    private String httpGet(String url, int maxBytes, boolean httpsOnly) throws Exception {
        return new String(downloadBytes(url, maxBytes, httpsOnly), StandardCharsets.UTF_8);
    }

    private static byte[] downloadBytes(String raw, int maxBytes, boolean httpsOnly) throws Exception {
        URL url = new URL(raw);
        long deadline = System.currentTimeMillis() + MAX_DOWNLOAD_MILLIS;
        for (int hop = 0; hop < 3; hop++) {
            if (httpsOnly && !"https".equalsIgnoreCase(url.getProtocol())) {
                throw new java.io.IOException("HTTPS required");
            }
            int timeout = remaining(deadline);
            HttpURLConnection c = (HttpURLConnection) url.openConnection();
            c.setInstanceFollowRedirects(false);
            c.setRequestMethod("GET");
            c.setRequestProperty("User-Agent", "Bulwark");
            c.setConnectTimeout(Math.min(8000, timeout));
            c.setReadTimeout(Math.min(8000, timeout));
            int code = c.getResponseCode();
            if (code >= 300 && code < 400) {
                String location = c.getHeaderField("Location");
                c.disconnect();
                if (!sameHostRedirect(url, location)) {
                    throw new java.io.IOException("redirect rejected");
                }
                url = new URL(url, location);
                continue;
            }
            if (code >= 400) {
                c.disconnect();
                throw new java.io.IOException("HTTP " + code);
            }
            c.setReadTimeout(Math.min(8000, remaining(deadline)));
            try (InputStream in = c.getInputStream()) {
                byte[] data = readLimited(in, maxBytes + 1, deadline);
                if (data.length > maxBytes) {
                    throw new java.io.IOException("response too large");
                }
                return data;
            } finally {
                c.disconnect();
            }
        }
        throw new java.io.IOException("too many redirects");
    }

    private static int remaining(long deadline) throws java.io.IOException {
        long left = deadline - System.currentTimeMillis();
        if (left <= 0) {
            throw new java.io.IOException("download timed out");
        }
        return (int) Math.min(Integer.MAX_VALUE, left);
    }

    static boolean sameHostRedirect(URL from, String location) {
        if (from == null || location == null || location.trim().isEmpty()) {
            return false;
        }
        try {
            URL to = new URL(from, location);
            return from.getProtocol().equalsIgnoreCase(to.getProtocol())
                    && from.getHost().equalsIgnoreCase(to.getHost())
                    && port(from) == port(to);
        } catch (Exception ex) {
            return false;
        }
    }

    private static int port(URL url) {
        if (url.getPort() >= 0) {
            return url.getPort();
        }
        return url.getDefaultPort();
    }

    static boolean shouldNotify(String latest, String notifiedVersion) {
        return latest != null && !latest.equals(notifiedVersion);
    }

    private static String parseVersion(String body) {
        if (body == null) {
            return "";
        }
        Matcher m = JSON_VERSION.matcher(body);
        if (m.find()) {
            return m.group(1).trim();
        }
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                String t = line.trim();
                if (!t.isEmpty()) {
                    return t;
                }
            }
        } catch (Exception ignored) {
        }
        return "";
    }

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
        if (s.toLowerCase(Locale.ROOT).startsWith("v")) {
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

    private PublicKey publicKey() {
        String pem = PUBLIC_KEY_PEM.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        try {
            byte[] der = Base64.getDecoder().decode(pem);
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception ex) {
            return null;
        }
    }

    static boolean verifyManifest(PublicKey publicKey, String kind, Manifest manifest) {
        if (manifest == null || !manifest.complete()) {
            return false;
        }
        if (!httpsUrl(manifest.url)) {
            return false;
        }
        return verifySig(publicKey, payload(kind, manifest.version, manifest.url, manifest.sha256), manifest.signature);
    }

    static boolean verifySig(PublicKey publicKey, byte[] payload, String sigB64) {
        if (publicKey == null || payload == null || sigB64 == null || sigB64.trim().isEmpty()) {
            return false;
        }
        try {
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            verifier.update(payload);
            return verifier.verify(Base64.getDecoder().decode(sigB64));
        } catch (Exception ex) {
            return false;
        }
    }

    static byte[] payload(String... parts) {
        StringBuilder sb = new StringBuilder();
        for (String part : parts) {
            String p = part == null ? "" : part;
            sb.append(p.length()).append(':').append(p);
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    static String sha256(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(bytes == null ? new byte[0] : bytes);
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) {
                sb.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
            }
            return sb.toString();
        } catch (Exception ex) {
            return "";
        }
    }

    static boolean hashMatches(byte[] bytes, String expected) {
        return expected != null && sha256(bytes).equalsIgnoreCase(expected.trim());
    }

    static boolean validRemoteRules(byte[] bytes) {
        if (bytes == null || bytes.length == 0 || bytes.length > MAX_RULE_BYTES) {
            return false;
        }
        CommunityRules rules = CommunityRules.load(new ByteArrayInputStream(bytes), "remote");
        return !rules.rules().isEmpty() && !rules.diagnostics.hasIssues();
    }

    static byte[] readLimited(InputStream in, int max, long deadline) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int total = 0;
        int n;
        while (true) {
            remaining(deadline);
            n = in.read(buf);
            if (n == -1) {
                break;
            }
            int take = Math.min(n, max - total);
            if (take > 0) {
                out.write(buf, 0, take);
                total += take;
            }
            if (total >= max) {
                break;
            }
            remaining(deadline);
        }
        return out.toByteArray();
    }

    private static String safeVersion(String version) {
        String v = version == null ? "" : version.trim();
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '.' || c == '-' || c == '_') {
                out.append(c);
            }
        }
        return out.length() == 0 ? "update" : out.toString();
    }

    static File destinationJar(File updateDir, File installed, String version) {
        String name = installed == null ? "" : installed.getName();
        if (name.isEmpty() || !name.toLowerCase(Locale.ROOT).endsWith(".jar")) {
            name = "Bulwark-" + safeVersion(version) + ".jar";
        }
        return new File(updateDir, name);
    }

    private static boolean httpsUrl(String raw) {
        try {
            return "https".equalsIgnoreCase(new URL(raw).getProtocol());
        } catch (Exception ex) {
            return false;
        }
    }

    private static void deleteQuietly(File file) {
        try {
            if (file != null && file.isFile()) {
                file.delete();
            }
        } catch (Throwable ignored) {
        }
    }

    static final class Manifest {
        static final Manifest EMPTY = new Manifest("", "", "", "");

        final String version;
        final String url;
        final String sha256;
        final String signature;

        Manifest(String version, String url, String sha256, String signature) {
            this.version = version == null ? "" : version.trim();
            this.url = url == null ? "" : url.trim();
            this.sha256 = sha256 == null ? "" : sha256.trim();
            this.signature = signature == null ? "" : signature.trim();
        }

        boolean complete() {
            return !version.isEmpty() && !url.isEmpty() && sha256.matches("(?i)[0-9a-f]{64}") && !signature.isEmpty();
        }

        static Manifest parse(String body) {
            if (body == null || body.trim().isEmpty()) {
                return EMPTY;
            }
            return new Manifest(field(body, "version"), field(body, "url"), field(body, "sha256"),
                    first(field(body, "signature"), field(body, "sig")));
        }

        private static String field(String body, String key) {
            Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]*)\"").matcher(body);
            return m.find() ? m.group(1).trim() : "";
        }

        private static String first(String a, String b) {
            return a == null || a.isEmpty() ? b : a;
        }
    }
}
