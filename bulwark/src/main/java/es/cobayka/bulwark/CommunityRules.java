package es.cobayka.bulwark;

import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

final class CommunityRules {
    static final String CATEGORY = "community-rules";
    private static final int ENGINE = 1;
    private static final int MAX_RULE_FILE = 262144;
    private static final int MAX_CONFIG_FILE = 131072;
    private static final int MAX_RULES = 64;
    private static final int MAX_DEPTH = 6;
    private static final int MAX_STRING = 768;
    private static final int MAX_SOURCES = 5;
    private static final String RESOURCE = "rules/community-rules.yml";

    final RulePackInfo pack;
    final List<Rule> rules;
    final RuleDiagnostics diagnostics;

    private CommunityRules(RulePackInfo pack, List<Rule> rules, RuleDiagnostics diagnostics) {
        this.pack = pack;
        this.rules = Collections.unmodifiableList(new ArrayList<>(rules));
        this.diagnostics = diagnostics;
    }

    static CommunityRules bundled(JavaPlugin plugin) {
        CommunityRules bundled = bundledOnly(plugin);
        CommunityRules downloaded = downloaded(plugin);
        if (downloaded != null && UpdateChecker.isNewer(downloaded.pack.version, bundled.pack.version)) {
            return downloaded;
        }
        return bundled;
    }

    static String localVersion(JavaPlugin plugin) {
        CommunityRules bundled = bundledOnly(plugin);
        CommunityRules downloaded = downloadedFile(plugin);
        return downloaded != null && UpdateChecker.isNewer(downloaded.pack.version, bundled.pack.version)
                ? downloaded.pack.version : bundled.pack.version;
    }

    private static CommunityRules bundledOnly(JavaPlugin plugin) {
        try (InputStream in = plugin.getResource(RESOURCE)) {
            return load(in, RESOURCE);
        } catch (Throwable t) {
            RuleDiagnostics d = new RuleDiagnostics();
            d.skip("ruleset", safeMessage(t));
            return new CommunityRules(RulePackInfo.EMPTY, Collections.<Rule>emptyList(), d);
        }
    }

    static String bundledVersion(JavaPlugin plugin) {
        try (InputStream in = plugin.getResource(RESOURCE)) {
            return load(in, RESOURCE).pack.version;
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static CommunityRules downloaded(JavaPlugin plugin) {
        if (plugin == null || UpdateChecker.mode(plugin.getConfig().get("rules.update"), null, UpdateChecker.Mode.OFF) != UpdateChecker.Mode.DOWNLOAD) {
            return null;
        }
        return downloadedFile(plugin);
    }

    private static CommunityRules downloadedFile(JavaPlugin plugin) {
        if (plugin == null) {
            return null;
        }
        File file = new File(plugin.getDataFolder(), "community-rules.yml");
        if (!file.isFile() || file.length() <= 0 || file.length() > MAX_RULE_FILE) {
            return null;
        }
        try (InputStream in = new FileInputStream(file)) {
            CommunityRules rules = load(in, file.getName());
            return !rules.rules.isEmpty() && !rules.diagnostics.hasIssues() ? rules : null;
        } catch (Throwable ignored) {
            return null;
        }
    }

    static CommunityRules load(InputStream in, String source) {
        RuleDiagnostics d = new RuleDiagnostics();
        if (in == null) {
            d.skip("ruleset", "missing");
            return new CommunityRules(RulePackInfo.EMPTY, Collections.<Rule>emptyList(), d);
        }
        try {
            byte[] bytes = readLimited(in, MAX_RULE_FILE + 1);
            if (bytes.length > MAX_RULE_FILE) {
                d.skip("ruleset", "file too large");
                return new CommunityRules(RulePackInfo.EMPTY, Collections.<Rule>emptyList(), d);
            }
            YamlConfiguration yaml = YamlConfiguration.loadConfiguration(
                    new InputStreamReader(new ByteArrayInputStream(bytes), StandardCharsets.UTF_8));
            RulePackInfo pack = pack(yaml, source);
            if (pack.minEngine > ENGINE) {
                d.skip("ruleset", "requires newer engine");
                return new CommunityRules(pack, Collections.<Rule>emptyList(), d);
            }
            if (forbidden(yaml.getValues(true))) {
                d.skip("ruleset", "forbidden executable matcher");
                return new CommunityRules(pack, Collections.<Rule>emptyList(), d);
            }
            List<Map<?, ?>> rows = yaml.getMapList("rules");
            List<Rule> rules = new ArrayList<>();
            if (rows.size() > MAX_RULES) {
                d.skip("ruleset", "too many rules");
                rows = rows.subList(0, MAX_RULES);
            }
            if (rows.isEmpty()) {
                d.skip("ruleset", "no rules");
                return new CommunityRules(pack, Collections.<Rule>emptyList(), d);
            }
            for (Map<?, ?> row : rows) {
                String id = string(row, "id");
                try {
                    if (forbiddenObject(row)) {
                        d.skip(id, "forbidden executable matcher");
                        continue;
                    }
                    Rule rule = parseRule(row, d);
                    if (rule != null) {
                        rules.add(rule);
                        d.loaded();
                    }
                } catch (Throwable t) {
                    d.skip(id, safeMessage(t));
                }
            }
            return new CommunityRules(pack, rules, d);
        } catch (Throwable t) {
            d.skip("ruleset", safeMessage(t));
            return new CommunityRules(RulePackInfo.EMPTY, Collections.<Rule>emptyList(), d);
        }
    }

    Evaluation evaluate(Context ctx) {
        List<Finding> out = new ArrayList<>();
        for (Rule rule : rules) {
            try {
                ctx.clearVersionUncertain();
                RuleMatch match = rule.evaluate(ctx);
                ctx.clearVersionUncertain();
                if (match != null) {
                    out.add(match.finding());
                }
            } catch (Throwable t) {
                diagnostics.skip(rule.id, safeMessage(t));
            }
        }
        if (diagnostics.hasIssues()) {
            out.add(new Finding("community.rules.diagnostics", CATEGORY, Severity.INFO,
                    "Community rules diagnostics",
                    "Bulwark skipped invalid bundled community rule data. " + diagnostics.summary() + ".",
                    "Update Bulwark or report this ruleset issue to Cobayka.", Baseline.COMMUNITY));
        }
        out.sort((a, b) -> a.severity.ordinal() - b.severity.ordinal());
        return new Evaluation(out, diagnostics);
    }

    List<Rule> rules() {
        return rules;
    }

    private static RulePackInfo pack(YamlConfiguration yaml, String source) {
        String id = yaml.getString("ruleset.id", "");
        String version = yaml.getString("ruleset.version", "");
        int min = yaml.getInt("ruleset.minEngine", 1);
        return new RulePackInfo(id, version, min, source);
    }

    private static Rule parseRule(Map<?, ?> row, RuleDiagnostics d) {
        String id = limited(required(row, "id"));
        if (!id.matches("[a-z0-9][a-z0-9._-]{5,119}")) {
            throw new IllegalArgumentException("invalid id");
        }
        Severity severity = severity(required(row, "severity"));
        Object whenRaw = row.get("when");
        if (versionUnknown(whenRaw) && severity.ordinal() < Severity.LOW.ordinal()) {
            throw new IllegalArgumentException("versionUnknown can only be LOW or INFO");
        }
        List<String> sources = sources(row.get("sources"));
        Rule.Condition when = condition(whenRaw, 0);
        return new Rule(id, severity, limited(value(row, "category", CATEGORY)),
                limited(required(row, "title")), limited(required(row, "detail")),
                limited(required(row, "fix")), sources, when);
    }

    private static Rule.Condition condition(Object raw, int depth) {
        if (depth > MAX_DEPTH) {
            throw new IllegalArgumentException("condition tree too deep");
        }
        Map<?, ?> map = map(raw);
        if (map.containsKey("all")) {
            return all(conditions(map.get("all"), depth + 1));
        }
        if (map.containsKey("any")) {
            return any(conditions(map.get("any"), depth + 1));
        }
        if (map.containsKey("not")) {
            return not(condition(map.get("not"), depth + 1));
        }
        if (map.containsKey("plugin")) {
            return artifact(map.get("plugin"), true);
        }
        if (map.containsKey("artifact")) {
            return artifact(map.get("artifact"), false);
        }
        if (map.containsKey("serverProperty")) {
            return serverProperty(map.get("serverProperty"));
        }
        if (map.containsKey("yamlConfig")) {
            return yamlConfig(map.get("yamlConfig"));
        }
        if (map.containsKey("server")) {
            return server(map.get("server"));
        }
        if (map.containsKey("protection")) {
            return protection(map.get("protection"));
        }
        if (map.containsKey("posture")) {
            return posture(map.get("posture"));
        }
        throw new IllegalArgumentException("unknown condition");
    }

    private static List<Rule.Condition> conditions(Object raw, int depth) {
        List<?> list = list(raw);
        if (list.isEmpty() || list.size() > 12) {
            throw new IllegalArgumentException("invalid condition list");
        }
        List<Rule.Condition> out = new ArrayList<>();
        for (Object item : list) {
            out.add(condition(item, depth));
        }
        return out;
    }

    private static Rule.Condition all(final List<Rule.Condition> conditions) {
        return (ctx, rule) -> {
            List<String> evidence = new ArrayList<>();
            Severity severity = rule.severity;
            boolean verifyManually = false;
            for (Rule.Condition c : conditions) {
                RuleMatch m = c.match(ctx, rule);
                if (m == null) {
                    return null;
                }
                if (!m.evidence.isEmpty()) {
                    evidence.add(m.evidence);
                }
                if (m.severity.ordinal() > severity.ordinal()) {
                    severity = m.severity;
                }
                verifyManually |= m.verifyManually;
            }
            return new RuleMatch(rule, String.join("; ", evidence), severity, verifyManually);
        };
    }

    private static Rule.Condition any(final List<Rule.Condition> conditions) {
        return (ctx, rule) -> {
            for (Rule.Condition c : conditions) {
                RuleMatch m = c.match(ctx, rule);
                if (m != null) {
                    return m;
                }
            }
            return null;
        };
    }

    private static Rule.Condition not(final Rule.Condition inner) {
        return (ctx, rule) -> {
            ctx.clearVersionUncertain();
            RuleMatch m = inner.match(ctx, rule);
            boolean uncertain = ctx.consumeVersionUncertain();
            if (m != null) {
                return null;
            }
            return uncertain ? inferredMatch(rule, "negated condition matched (version source: unknown)")
                    : match(rule, "negated condition matched");
        };
    }

    private static RuleMatch match(Rule rule, String evidence) {
        return new RuleMatch(rule, Redactor.redact(evidence));
    }

    private static RuleMatch inferredMatch(Rule rule, String evidence) {
        return new RuleMatch(rule, Redactor.redact(evidence), Severity.INFO, true);
    }

    private static Rule.Condition artifact(Object raw, boolean pluginOnly) {
        final Map<?, ?> map = map(raw);
        final Set<String> names = names(map);
        final String type = pluginOnly ? "plugin" : norm(string(map, "type"));
        final String loader = norm(string(map, "loader"));
        final String pathScope = norm(string(map, "pathScope"));
        final boolean hasVersion = map.containsKey("version");
        final VersionSpec version = hasVersion ? version(map.get("version")) : VersionSpec.ANY;
        if (names.isEmpty()) {
            throw new IllegalArgumentException("artifact name missing");
        }
        return (ctx, rule) -> {
            for (MinecraftInventory.Item item : ctx.inventory.items) {
                if (disabled(item)) {
                    continue;
                }
                if (!type.isEmpty() && !type.equals(norm(item.type))) {
                    continue;
                }
                if (!loader.isEmpty() && !loader.equals(norm(item.loader))) {
                    continue;
                }
                if (!pathScope.isEmpty() && !pathScope.equals(scope(item.path))) {
                    continue;
                }
                if (!matchesName(names, item)) {
                    continue;
                }
                String matchedVersion = item.version;
                String source = "metadata";
                boolean inferred = false;
                int versionState = version.match(matchedVersion);
                if (versionState == VersionRange.UNKNOWN && !version.versionUnknown) {
                    String pathVersion = versionFromPath(item.path);
                    if (!pathVersion.isEmpty()) {
                        int pathState = version.match(pathVersion);
                        if (pathState == VersionRange.MATCH) {
                            versionState = pathState;
                            matchedVersion = pathVersion;
                            source = "jar filename";
                            inferred = true;
                        } else if (pathState == VersionRange.NO_MATCH) {
                            versionState = pathState;
                        }
                    }
                }
                if (versionState == VersionRange.NO_MATCH) {
                    continue;
                }
                if (versionState == VersionRange.UNKNOWN && !version.versionUnknown) {
                    ctx.markVersionUncertain();
                    continue;
                }
                if (hasVersion && versionState == VersionRange.MATCH && !inferred && !cleanMetadataVersion(matchedVersion)) {
                    source = "ambiguous metadata";
                    inferred = true;
                }
                if (versionState == VersionRange.UNKNOWN && version.versionUnknown) {
                    source = "unparseable metadata";
                    inferred = true;
                }
                String v = matchedVersion == null || matchedVersion.trim().isEmpty() ? "version unknown" : matchedVersion.trim();
                String suffix = hasVersion ? " (version source: " + source + ")" : "";
                String evidence = item.path + " declares " + item.name + " " + v + suffix;
                return inferred ? inferredMatch(rule, evidence) : match(rule, evidence);
            }
            return null;
        };
    }

    private static Rule.Condition serverProperty(Object raw) {
        final Map<?, ?> map = map(raw);
        final String key = required(map, "key");
        final String equals = string(map, "equals");
        final boolean present = bool(map, "present");
        return (ctx, rule) -> {
            String value = ctx.props.getProperty(key, "").trim();
            if (present) {
                return value.isEmpty() ? null : match(rule, "server.properties contains " + key);
            }
            if (!equals.isEmpty() && equals.equalsIgnoreCase(value)) {
                return match(rule, "server.properties " + key + "=" + equals);
            }
            return null;
        };
    }

    private static Rule.Condition yamlConfig(Object raw) {
        final Map<?, ?> map = map(raw);
        final String path = limited(required(map, "path"));
        final String key = limited(required(map, "key"));
        final String equals = string(map, "equals");
        final boolean present = bool(map, "present");
        return (ctx, rule) -> {
            YamlConfiguration yaml = ctx.yaml(path);
            if (yaml == null) {
                return null;
            }
            if (present && yaml.contains(key)) {
                return match(rule, path + " contains " + key);
            }
            if (!equals.isEmpty()) {
                String value = yaml.getString(key, "");
                if (equals.equalsIgnoreCase(value == null ? "" : value.trim())) {
                    return match(rule, path + " has " + key + "=" + equals);
                }
            }
            return null;
        };
    }

    private static Rule.Condition server(Object raw) {
        final Map<?, ?> map = map(raw);
        final String platform = norm(string(map, "platform"));
        final String loader = norm(string(map, "loader"));
        final VersionSpec version = version(map.get("version"));
        return (ctx, rule) -> {
            if (!platform.isEmpty() && !norm(ctx.platform).contains(platform)) {
                return null;
            }
            if (!loader.isEmpty() && !norm(ctx.loader).contains(loader)) {
                return null;
            }
            int v = version.match(ctx.mcVersion);
            if (v == VersionRange.NO_MATCH || (v == VersionRange.UNKNOWN && !version.versionUnknown)) {
                return null;
            }
            return match(rule, "server " + ctx.platform + " " + ctx.mcVersion + " / " + ctx.loader);
        };
    }

    private static Rule.Condition protection(Object raw) {
        final Map<?, ?> map = map(raw);
        final String missing = string(map, "categoryMissing");
        return (ctx, rule) -> {
            if (missing.isEmpty() || ctx.registry == null) {
                return null;
            }
            try {
                PluginRegistry.Category cat = PluginRegistry.Category.valueOf(missing.trim().toUpperCase(Locale.ROOT).replace('-', '_'));
                return ctx.registry.has(cat) ? null : match(rule, "missing " + missing + " protection category");
            } catch (IllegalArgumentException ex) {
                return null;
            }
        };
    }

    private static Rule.Condition posture(Object raw) {
        final Map<?, ?> map = map(raw);
        final String profile = norm(string(map, "profile"));
        return (ctx, rule) -> !profile.isEmpty() && profile.equals(norm(ctx.posture))
                ? match(rule, "posture " + ctx.posture) : null;
    }

    private static VersionSpec version(Object raw) {
        if (raw == null) {
            throw new IllegalArgumentException("missing version range");
        }
        Map<?, ?> map = map(raw);
        String prefix = string(map, "prefix");
        boolean unknown = bool(map, "versionUnknown");
        List<VersionRange> ranges = new ArrayList<>();
        Object any = map.get("any");
        if (any != null) {
            for (Object item : list(any)) {
                addRange(ranges, String.valueOf(item));
            }
        }
        String direct = directRange(map);
        addRange(ranges, direct);
        if (ranges.isEmpty() && !unknown) {
            throw new IllegalArgumentException("missing version range");
        }
        return new VersionSpec(prefix, ranges, unknown);
    }

    private static boolean cleanMetadataVersion(String version) {
        if (version == null) {
            return false;
        }
        String v = version.trim().toLowerCase(Locale.ROOT);
        if (v.startsWith("v") && v.length() > 1 && Character.isDigit(v.charAt(1))) {
            v = v.substring(1);
        }
        int plus = v.indexOf('+');
        if (plus >= 0) {
            v = v.substring(0, plus);
        }
        if (v.endsWith("-snapshot")) {
            v = v.substring(0, v.length() - "-snapshot".length());
        } else if (v.matches(".*-rc\\d*$")) {
            v = v.substring(0, v.lastIndexOf("-rc"));
        }
        return v.matches("\\d+(?:\\.\\d+){1,2}");
    }

    private static String directRange(Map<?, ?> map) {
        List<String> parts = new ArrayList<>();
        addPart(parts, string(map, "range"));
        addPart(parts, string(map, "lt").isEmpty() ? "" : "< " + string(map, "lt"));
        addPart(parts, string(map, "lte").isEmpty() ? "" : "<= " + string(map, "lte"));
        addPart(parts, string(map, "gt").isEmpty() ? "" : "> " + string(map, "gt"));
        addPart(parts, string(map, "gte").isEmpty() ? "" : ">= " + string(map, "gte"));
        addPart(parts, string(map, "eq").isEmpty() ? "" : "= " + string(map, "eq"));
        return String.join(" ", parts);
    }

    private static void addPart(List<String> parts, String value) {
        if (value != null && !value.trim().isEmpty()) {
            parts.add(value.trim());
        }
    }

    private static void addRange(List<VersionRange> ranges, String expression) {
        if (expression == null || expression.trim().isEmpty()) {
            return;
        }
        VersionRange range = VersionRange.parse(expression);
        if (!range.valid()) {
            throw new IllegalArgumentException("invalid version range");
        }
        ranges.add(range);
    }

    private static boolean matchesName(Set<String> names, MinecraftInventory.Item item) {
        if (names.contains(norm(item.name))) {
            return true;
        }
        String base = item.path;
        int slash = Math.max(base.lastIndexOf('/'), base.lastIndexOf('\\'));
        if (slash >= 0) {
            base = base.substring(slash + 1);
        }
        if (base.toLowerCase(Locale.ROOT).endsWith(".jar")) {
            base = base.substring(0, base.length() - 4);
        }
        if (base.toLowerCase(Locale.ROOT).endsWith(".disabled")) {
            base = base.substring(0, base.length() - ".disabled".length());
        }
        return names.contains(norm(base));
    }

    private static boolean disabled(MinecraftInventory.Item item) {
        String p = item.path == null ? "" : item.path.toLowerCase(Locale.ROOT);
        if (p.endsWith(".disabled") || p.endsWith(".jar.disabled")) {
            return true;
        }
        for (String flag : item.flags) {
            if ("disabled".equalsIgnoreCase(flag)) {
                return true;
            }
        }
        return false;
    }

    private static String versionFromPath(String path) {
        if (path == null || path.trim().isEmpty()) {
            return "";
        }
        String base = path.replace('\\', '/');
        int slash = base.lastIndexOf('/');
        if (slash >= 0) {
            base = base.substring(slash + 1);
        }
        String lower = base.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".disabled")) {
            base = base.substring(0, base.length() - ".disabled".length());
            lower = base.toLowerCase(Locale.ROOT);
        }
        if (lower.endsWith(".jar")) {
            base = base.substring(0, base.length() - 4);
        }
        int start = -1;
        for (int i = 0; i < base.length(); i++) {
            if (Character.isDigit(base.charAt(i))) {
                start = i;
                break;
            }
        }
        return start < 0 ? "" : base.substring(start);
    }

    private static String scope(String path) {
        String p = path == null ? "" : path.replace('\\', '/').toLowerCase(Locale.ROOT);
        int slash = p.indexOf('/');
        return slash < 0 ? "root" : norm(p.substring(0, slash));
    }

    private static Set<String> names(Map<?, ?> map) {
        Set<String> out = new HashSet<>();
        String name = string(map, "name");
        if (!name.isEmpty()) {
            out.add(norm(name));
        }
        String id = string(map, "id");
        if (!id.isEmpty()) {
            out.add(norm(id));
        }
        Object names = map.get("names");
        if (names != null) {
            for (Object item : list(names)) {
                String n = norm(String.valueOf(item));
                if (!n.isEmpty()) {
                    out.add(n);
                }
            }
        }
        return out;
    }

    private static Severity severity(String raw) {
        try {
            return Severity.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (Exception ex) {
            throw new IllegalArgumentException("invalid severity");
        }
    }

    private static List<String> sources(Object raw) {
        List<String> out = new ArrayList<>();
        if (raw == null) {
            return out;
        }
        for (Object value : list(raw)) {
            String s = limited(String.valueOf(value));
            if (!s.startsWith("https://")) {
                throw new IllegalArgumentException("invalid source");
            }
            if (out.size() < MAX_SOURCES) {
                out.add(s);
            }
        }
        return out;
    }

    private static boolean forbidden(Map<String, Object> values) {
        for (String key : values.keySet()) {
            String k = key.toLowerCase(Locale.ROOT);
            if (k.contains("regex") || k.contains("script") || k.contains("exec") || k.contains("urlfetch")) {
                return true;
            }
        }
        return false;
    }

    private static boolean forbiddenObject(Object raw) {
        if (raw instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) raw;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String key = String.valueOf(entry.getKey()).toLowerCase(Locale.ROOT);
                if (key.contains("regex") || key.contains("script") || key.contains("exec") || key.contains("urlfetch")) {
                    return true;
                }
                if (forbiddenObject(entry.getValue())) {
                    return true;
                }
            }
        } else if (raw instanceof List) {
            for (Object item : (List<?>) raw) {
                if (forbiddenObject(item)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean versionUnknown(Object raw) {
        if (raw instanceof Map) {
            Map<?, ?> m = (Map<?, ?>) raw;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if ("versionUnknown".equalsIgnoreCase(String.valueOf(e.getKey())) && truthy(e.getValue())) {
                    return true;
                }
                if (versionUnknown(e.getValue())) {
                    return true;
                }
            }
        } else if (raw instanceof List) {
            for (Object o : (List<?>) raw) {
                if (versionUnknown(o)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static Map<?, ?> map(Object raw) {
        if (raw instanceof Map) {
            return (Map<?, ?>) raw;
        }
        throw new IllegalArgumentException("expected map");
    }

    private static List<?> list(Object raw) {
        if (raw instanceof List) {
            return (List<?>) raw;
        }
        if (raw == null) {
            return Collections.emptyList();
        }
        List<Object> one = new ArrayList<>();
        one.add(raw);
        return one;
    }

    private static String required(Map<?, ?> map, String key) {
        String v = string(map, key);
        if (v.isEmpty()) {
            throw new IllegalArgumentException("missing " + key);
        }
        return v;
    }

    private static String value(Map<?, ?> map, String key, String fallback) {
        String v = string(map, key);
        return v.isEmpty() ? fallback : v;
    }

    private static String string(Map<?, ?> map, String key) {
        Object value = map.get(key);
        return value == null ? "" : String.valueOf(value).trim();
    }

    private static boolean bool(Map<?, ?> map, String key) {
        return truthy(map.get(key));
    }

    private static boolean truthy(Object value) {
        return value instanceof Boolean ? (Boolean) value : "true".equalsIgnoreCase(String.valueOf(value));
    }

    private static String limited(String value) {
        if (value == null) {
            return "";
        }
        String v = value.trim();
        if (v.length() > MAX_STRING) {
            throw new IllegalArgumentException("string too long");
        }
        return v;
    }

    private static String norm(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder b = new StringBuilder();
        String lower = value.toLowerCase(Locale.ROOT);
        for (int i = 0; i < lower.length(); i++) {
            char c = lower.charAt(i);
            if (Character.isLetterOrDigit(c)) {
                b.append(c);
            }
        }
        return b.toString();
    }

    private static String safeMessage(Throwable t) {
        String name = t == null ? "error" : t.getClass().getSimpleName();
        String msg = t == null || t.getMessage() == null ? "" : t.getMessage();
        msg = msg.replace('\n', ' ').replace('\r', ' ');
        if (msg.length() > 120) {
            msg = msg.substring(0, 120);
        }
        return msg.isEmpty() ? name : name + ": " + msg;
    }

    private static byte[] readLimited(InputStream in, int max) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int total = 0;
        int n;
        while ((n = in.read(buf)) != -1) {
            int take = Math.min(n, max - total);
            if (take > 0) {
                out.write(buf, 0, take);
                total += take;
            }
            if (total >= max) {
                break;
            }
        }
        return out.toByteArray();
    }

    static final class Evaluation {
        final List<Finding> findings;
        final RuleDiagnostics diagnostics;

        Evaluation(List<Finding> findings, RuleDiagnostics diagnostics) {
            this.findings = Collections.unmodifiableList(new ArrayList<>(findings));
            this.diagnostics = diagnostics;
        }
    }

    static final class Context {
        final MinecraftInventory.Result inventory;
        final Properties props;
        final String platform;
        final String loader;
        final String mcVersion;
        final String posture;
        final PluginRegistry registry;
        private final ServerEnv env;
        private final Map<String, YamlConfiguration> yaml = new HashMap<>();
        private boolean versionUncertain;

        Context(MinecraftInventory.Result inventory, Properties props, ServerProfile profile,
                PostureProfile posture, PluginRegistry registry, ServerEnv env) {
            this.inventory = inventory == null ? new MinecraftInventory.Result(Collections.<MinecraftInventory.Item>emptyList()) : inventory;
            this.props = props == null ? new Properties() : props;
            this.platform = profile == null ? "" : profile.platform;
            this.loader = profile == null ? "" : profile.loader;
            this.mcVersion = profile == null ? "" : profile.mcVersion;
            this.posture = posture == null ? "" : posture.active;
            this.registry = registry;
            this.env = env;
        }

        Context(MinecraftInventory.Result inventory, Properties props, String platform,
                String loader, String mcVersion, String posture, PluginRegistry registry,
                ServerEnv env, Map<String, YamlConfiguration> yaml) {
            this.inventory = inventory == null ? new MinecraftInventory.Result(Collections.<MinecraftInventory.Item>emptyList()) : inventory;
            this.props = props == null ? new Properties() : props;
            this.platform = platform == null ? "" : platform;
            this.loader = loader == null ? "" : loader;
            this.mcVersion = mcVersion == null ? "" : mcVersion;
            this.posture = posture == null ? "" : posture;
            this.registry = registry;
            this.env = env;
            if (yaml != null) {
                this.yaml.putAll(yaml);
            }
        }

        YamlConfiguration yaml(String path) {
            YamlConfiguration cached = yaml.get(path);
            if (cached != null) {
                return cached;
            }
            if (env == null || !safePath(path)) {
                return null;
            }
            try {
                File root = env.root().getCanonicalFile();
                File file = new File(root, path).getCanonicalFile();
                String rootPath = root.getPath();
                String filePath = file.getPath();
                if (!filePath.equals(rootPath) && !filePath.startsWith(rootPath + File.separator)) {
                    return null;
                }
                if (!file.isFile() || file.length() > MAX_CONFIG_FILE) {
                    return null;
                }
                YamlConfiguration y = YamlConfiguration.loadConfiguration(file);
                yaml.put(path, y);
                return y;
            } catch (Throwable ignored) {
                return null;
            }
        }

        void markVersionUncertain() {
            versionUncertain = true;
        }

        void clearVersionUncertain() {
            versionUncertain = false;
        }

        boolean consumeVersionUncertain() {
            boolean value = versionUncertain;
            versionUncertain = false;
            return value;
        }

        private static boolean safePath(String path) {
            if (path == null || path.trim().isEmpty() || path.length() > 180) {
                return false;
            }
            String p = path.replace('\\', '/');
            return !p.startsWith("/") && !p.contains("../") && !p.contains("/..") && !p.contains(":");
        }
    }

    private static final class VersionSpec {
        static final VersionSpec ANY = new VersionSpec("", Collections.<VersionRange>emptyList(), false);

        final String prefix;
        final List<VersionRange> ranges;
        final boolean versionUnknown;

        VersionSpec(String prefix, List<VersionRange> ranges, boolean versionUnknown) {
            this.prefix = prefix == null ? "" : prefix.trim();
            this.ranges = Collections.unmodifiableList(new ArrayList<>(ranges));
            this.versionUnknown = versionUnknown;
        }

        int match(String version) {
            String v = version == null ? "" : version.trim();
            if (ranges.isEmpty()) {
                if (versionUnknown) {
                    return VersionRange.parseable(v) ? VersionRange.NO_MATCH : VersionRange.UNKNOWN;
                }
                return VersionRange.MATCH;
            }
            if (!VersionRange.parseable(v)) {
                return VersionRange.UNKNOWN;
            }
            if (!prefix.isEmpty() && !v.startsWith(prefix)) {
                return VersionRange.NO_MATCH;
            }
            boolean unknown = false;
            for (VersionRange range : ranges) {
                int result = range.test(v);
                if (result == VersionRange.MATCH) {
                    return VersionRange.MATCH;
                }
                if (result == VersionRange.UNKNOWN) {
                    unknown = true;
                }
            }
            return unknown ? VersionRange.UNKNOWN : VersionRange.NO_MATCH;
        }
    }
}
