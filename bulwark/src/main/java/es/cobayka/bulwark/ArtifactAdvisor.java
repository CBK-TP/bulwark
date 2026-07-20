package es.cobayka.bulwark;

import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class ArtifactAdvisor {

    private static final Pattern VERSION = Pattern.compile("\"version_number\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern PROJECT = Pattern.compile("\"project_id\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern GHSA = Pattern.compile("\"ghsa_id\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern CVE = Pattern.compile("\"cve_id\"\\s*:\\s*(?:\"([^\"]+)\"|null)");
    private static final Pattern SEVERITY = Pattern.compile("\"severity\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern SUMMARY = Pattern.compile("\"summary\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern PUBLISHED = Pattern.compile("\"published_at\"\\s*:\\s*\"([^\"]+)\"");

    private final JavaPlugin plugin;
    private final ServerEnv env;

    ArtifactAdvisor(JavaPlugin plugin, ServerEnv env) {
        this.plugin = plugin;
        this.env = env;
    }

    List<String> check(MinecraftInventory.Item item) {
        List<String> out = new ArrayList<>();
        File file = file(item);
        if (file == null || !file.isFile() || !item.jar()) {
            out.add("This artifact is not a local jar, so version lookup is not available.");
            return out;
        }
        if (plugin.getConfig().getBoolean("advisory.modrinth", true)) {
            modrinth(item, file, out);
        }
        if (plugin.getConfig().getBoolean("advisory.github-advisories", true)) {
            github(item, out);
        }
        if (out.isEmpty()) {
            out.add("No advisory data returned by the enabled sources.");
        }
        return out;
    }

    private void modrinth(MinecraftInventory.Item item, File file, List<String> out) {
        String hash = sha512(file);
        if (hash.isEmpty()) {
            out.add("Modrinth: could not hash the jar.");
            return;
        }
        String body = "{\"hashes\":[\"" + hash + "\"],\"algorithm\":\"sha512\"}";
        String json = post("https://api.modrinth.com/v2/version_files", body);
        if (json.isEmpty() || "{}".equals(json.trim())) {
            out.add("Modrinth: no project matched this jar hash.");
            return;
        }
        String current = first(VERSION, json, item.version);
        String project = first(PROJECT, json, "");
        out.add("Modrinth: matched" + (project.isEmpty() ? "" : " project " + project) + ", version " + value(current, "?") + ".");

        String latestBody = "{\"hashes\":[\"" + hash + "\"],\"algorithm\":\"sha512\",\"loaders\":" + loaders(item)
                + ",\"game_versions\":" + gameVersions() + "}";
        String latestJson = post("https://api.modrinth.com/v2/version_files/update", latestBody);
        String latest = first(VERSION, latestJson, "");
        if (!latest.isEmpty()) {
            if (sameVersion(current, latest)) {
                out.add("Modrinth: version looks current for this server/loader.");
            } else {
                out.add("Modrinth: latest compatible version appears to be " + latest + ".");
            }
        }
    }

    private void github(MinecraftInventory.Item item, List<String> out) {
        String name = item.name == null || item.name.trim().isEmpty() ? item.path : item.name;
        try {
            String q = URLEncoder.encode(name, "UTF-8");
            String json = get("https://api.github.com/advisories?query=" + q + "&per_page=3");
            if (json.isEmpty() || "[]".equals(json.trim())) {
                out.add("GitHub advisories: no obvious public match for \"" + name + "\".");
                return;
            }
            Matcher ghsa = GHSA.matcher(json);
            Matcher sev = SEVERITY.matcher(json);
            Matcher sum = SUMMARY.matcher(json);
            Matcher pub = PUBLISHED.matcher(json);
            Matcher cve = CVE.matcher(json);
            int n = 0;
            while (ghsa.find() && n++ < 3) {
                String s = sev.find() ? sev.group(1) : "unknown";
                String title = sum.find() ? unescape(sum.group(1)) : "advisory";
                String published = pub.find() ? pub.group(1).split("T")[0] : "?";
                String c = cve.find() && cve.group(1) != null ? " " + cve.group(1) : "";
                out.add("GitHub advisories: possible " + s + " match " + ghsa.group(1) + c + " (" + published + ") - " + title);
            }
        } catch (Exception ex) {
            out.add("GitHub advisories: check failed (" + ex.getMessage() + ").");
        }
    }

    private String loaders(MinecraftInventory.Item item) {
        String loader = item.loader.toLowerCase(Locale.ROOT);
        if (loader.contains("fabric")) {
            return "[\"fabric\"]";
        }
        if (loader.contains("quilt")) {
            return "[\"quilt\"]";
        }
        if (loader.contains("neoforge")) {
            return "[\"neoforge\"]";
        }
        if (loader.contains("forge")) {
            return "[\"forge\"]";
        }
        if (loader.contains("velocity")) {
            return "[\"velocity\"]";
        }
        if (loader.contains("bungee")) {
            return "[\"bungeecord\"]";
        }
        return "[\"paper\",\"spigot\",\"bukkit\"]";
    }

    private String gameVersions() {
        String mc = "unknown";
        try {
            String v = plugin.getServer().getBukkitVersion();
            if (v != null && v.contains("-")) {
                mc = v.substring(0, v.indexOf('-'));
            } else if (v != null && !v.trim().isEmpty()) {
                mc = v.trim();
            }
        } catch (Throwable ignored) {
        }
        if (mc.matches("\\d+\\.\\d+\\.\\d+")) {
            return "[\"" + mc + "\",\"" + mc.substring(0, mc.lastIndexOf('.')) + "\"]";
        }
        return "[\"" + mc + "\"]";
    }

    private String get(String url) {
        return request("GET", url, null);
    }

    private String post(String url, String body) {
        return request("POST", url, body);
    }

    private String request(String method, String url, String body) {
        int timeout = Math.max(1000, plugin.getConfig().getInt("advisory.timeout-ms", 5000));
        try {
            HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
            c.setRequestMethod(method);
            c.setConnectTimeout(timeout);
            c.setReadTimeout(timeout);
            c.setRequestProperty("User-Agent", "Bulwark/" + plugin.getDescription().getVersion());
            c.setRequestProperty("Accept", "application/json");
            if (body != null) {
                byte[] bytes = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                c.setDoOutput(true);
                c.setRequestProperty("Content-Type", "application/json");
                c.setRequestProperty("Content-Length", String.valueOf(bytes.length));
                try (OutputStream out = c.getOutputStream()) {
                    out.write(bytes);
                }
            }
            int code = c.getResponseCode();
            InputStream in = code >= 200 && code < 300 ? c.getInputStream() : c.getErrorStream();
            if (in == null) {
                return "";
            }
            byte[] data = readLimited(in, 262144);
            return new String(data, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception ex) {
            return "";
        }
    }

    private File file(MinecraftInventory.Item item) {
        try {
            return new File(env.root(), item.path.replace('/', File.separatorChar)).getCanonicalFile();
        } catch (Exception ex) {
            return null;
        }
    }

    private static String sha512(File f) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
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

    private static byte[] readLimited(InputStream in, int max) throws Exception {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int total = 0;
        int n;
        while ((n = in.read(buf)) != -1 && total < max) {
            int take = Math.min(n, max - total);
            out.write(buf, 0, take);
            total += take;
        }
        return out.toByteArray();
    }

    private static String first(Pattern pattern, String text, String fallback) {
        if (text == null) {
            return fallback;
        }
        Matcher m = pattern.matcher(text);
        return m.find() ? m.group(1) : fallback;
    }

    private static String value(String s, String def) {
        return s == null || s.trim().isEmpty() ? def : s.trim();
    }

    private static boolean sameVersion(String a, String b) {
        return a != null && b != null && a.trim().equalsIgnoreCase(b.trim());
    }

    private static String unescape(String s) {
        return s.replace("\\\"", "\"").replace("\\n", " ").replace("\\/", "/");
    }
}
