package es.cobayka.bulwark;

import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Tiny i18n layer. English lives inline in the code as the source of truth and the ultimate
 * fallback; a language bundle (lang/&lt;code&gt;.yml, shipped in the jar and overridable in
 * plugins/Bulwark/lang/) supplies the translated strings. Lookups fall back to the inline English
 * key by key, so even a partial translation still works and a brand-new string is never blank.
 *
 * Placeholders are {0}, {1}, ... and are substituted with a plain replace - deliberately NOT
 * MessageFormat - so apostrophes ("Paper's") and large numbers (60000) in the text are never
 * mangled by quoting or locale grouping.
 *
 * One active instance per server, swapped atomically on reload; it's read-only after load, so it's
 * safe to read from the scheduler/drift threads and on Folia.
 */
final class Messages {

    private static volatile Messages active = new Messages("en", new HashMap<String, String>());

    private final String lang;
    private final Map<String, String> map; // flattened "a.b.c" -> value (empty for English)

    private Messages(String lang, Map<String, String> map) {
        this.lang = lang;
        this.map = map;
    }

    /** (Re)load the active bundle from the configured language. Call on enable and on reload. */
    static void init(JavaPlugin plugin, String language) {
        String lang = (language == null ? "" : language.trim().toLowerCase(Locale.ROOT));
        if (lang.isEmpty()) {
            lang = "en";
        }
        Map<String, String> flat = new HashMap<String, String>();
        if (!"en".equals(lang)) {
            // the jar bundle first, then a datafolder override layered on top
            mergeResource(plugin, "lang/" + lang + ".yml", flat);
            File f = new File(plugin.getDataFolder(), "lang/" + lang + ".yml");
            if (f.isFile()) {
                flatten(YamlConfiguration.loadConfiguration(f), flat);
            }
        }
        active = new Messages(lang, flat);
    }

    /** The active language code (e.g. "en", "es"). */
    static String lang() {
        return active.lang;
    }

    /** A general key with optional {0}.. placeholders; falls back to the English default. */
    static String t(String key, String enDefault, Object... args) {
        String v = active.map.get(key);
        return fill(v != null ? v : enDefault, args);
    }

    /** A finding's title/detail/fix, keyed by its id. */
    static String finding(String id, String field, String enDefault, Object... args) {
        return t("findings." + id + "." + field, enDefault, args);
    }

    private static String fill(String s, Object[] args) {
        if (s == null || args == null || args.length == 0) {
            return s;
        }
        for (int i = 0; i < args.length; i++) {
            s = s.replace("{" + i + "}", String.valueOf(args[i]));
        }
        return s;
    }

    private static void mergeResource(JavaPlugin plugin, String path, Map<String, String> out) {
        try (InputStream in = plugin.getResource(path)) {
            if (in != null) {
                flatten(YamlConfiguration.loadConfiguration(
                        new InputStreamReader(in, StandardCharsets.UTF_8)), out);
            }
        } catch (Exception ignored) {
            // a missing or broken bundle just means English - never fail the plugin over a translation
        }
    }

    private static void flatten(ConfigurationSection sec, Map<String, String> out) {
        for (String k : sec.getKeys(true)) {
            if (!sec.isConfigurationSection(k)) {
                Object v = sec.get(k);
                if (v != null) {
                    out.put(k, String.valueOf(v));
                }
            }
        }
    }
}
