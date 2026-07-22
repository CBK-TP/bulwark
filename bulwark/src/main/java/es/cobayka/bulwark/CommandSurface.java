package es.cobayka.bulwark;

import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.PluginIdentifiableCommand;
import org.bukkit.permissions.Permission;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

final class CommandSurface {

    private static final Set<String> DISCLOSURE = set("plugins", "pl", "version", "ver", "about", "icanhasbukkit");
    private static final Set<String> OP_NAMESPACE = set("op", "deop");
    private static final Set<String> PLUGIN_MANAGER = set("plugman", "plugmanx", "pluginmanager", "serverutils");
    private static final Set<String> DANGEROUS_DEFAULT = set("op", "deop", "lp", "luckperms", "pex", "permissionsex",
            "manuadd", "mangadd", "manuaddp", "plugman", "plugmanx", "pluginmanager");
    private static final Set<String> LIFECYCLE = set("stop", "restart", "reload", "rl", "save-all", "save-off", "save-on");
    private static final Set<String> SENSITIVE = set("op", "deop", "stop", "restart", "reload", "rl", "plugins", "pl",
            "version", "ver", "lp", "luckperms", "pex", "permissionsex", "plugman", "plugmanx", "pluginmanager");

    private final JavaPlugin plugin;

    CommandSurface(JavaPlugin plugin) {
        this.plugin = plugin;
    }

    static final class Entry {
        final String key;
        final String label;
        final String namespace;
        final boolean namespaced;
        final String owner;
        final String permission;
        final String permissionDefault;
        final int commandId;

        Entry(String key, Command command) {
            this.key = key;
            this.label = CommandClassifier.label(CommandClassifier.normalize(key));
            int colon = key.indexOf(':');
            this.namespaced = colon > 0;
            this.namespace = namespaced ? key.substring(0, colon) : "";
            this.owner = owner(command, namespace);
            this.permission = clean(command.getPermission());
            this.permissionDefault = declaredDefault(permission);
            this.commandId = System.identityHashCode(command);
        }

        Entry(String key, String owner, String permission, int commandId) {
            this.key = key;
            this.label = CommandClassifier.label(CommandClassifier.normalize(key));
            int colon = key.indexOf(':');
            this.namespaced = colon > 0;
            this.namespace = namespaced ? key.substring(0, colon) : "";
            this.owner = owner == null || owner.trim().isEmpty() ? "plugin.yml" : owner.trim();
            this.permission = clean(permission);
            this.permissionDefault = declaredDefault(this.permission);
            this.commandId = commandId;
        }

        boolean publicish() {
            return permission.isEmpty() || "TRUE".equals(permissionDefault);
        }

        boolean risky() {
            return DISCLOSURE.contains(label) || OP_NAMESPACE.contains(label) || PLUGIN_MANAGER.contains(label)
                    || DANGEROUS_DEFAULT.contains(label) || LIFECYCLE.contains(label) || SENSITIVE.contains(label);
        }

        String flags() {
            List<String> f = new ArrayList<>();
            if (DISCLOSURE.contains(label)) {
                f.add("disclosure");
            }
            if (namespaced && OP_NAMESPACE.contains(label)) {
                f.add("namespace");
            }
            if (PLUGIN_MANAGER.contains(label) || looksLikePluginManager(owner)) {
                f.add("plugin-manager");
            }
            if (DANGEROUS_DEFAULT.contains(label) && publicish()) {
                f.add("public-default");
            }
            if (LIFECYCLE.contains(label)) {
                f.add("lifecycle");
            }
            return f.isEmpty() ? "surface" : String.join(", ", f);
        }

        String line() {
            String perm = permission.isEmpty() ? "no declared permission" : permission + defaultSuffix();
            return key + " - " + owner + " - " + perm + " - " + flags();
        }

        private String defaultSuffix() {
            return permissionDefault.isEmpty() ? "" : " / default " + permissionDefault.toLowerCase(Locale.ROOT);
        }
    }

    static final class Duplicate {
        final String label;
        final List<Entry> entries;

        Duplicate(String label, List<Entry> entries) {
            this.label = label;
            this.entries = entries;
        }

        String line() {
            return label + " -> " + examples(entries, 6);
        }
    }

    static final class Result {
        final boolean available;
        final boolean partial;
        final String failure;
        final List<Entry> entries;

        Result(boolean available, boolean partial, String failure, List<Entry> entries) {
            this.available = available;
            this.partial = partial;
            this.failure = failure;
            this.entries = entries;
        }

        static Result unavailable(String failure) {
            return new Result(false, false, failure, Collections.<Entry>emptyList());
        }

        static Result partial(String failure, List<Entry> entries) {
            return new Result(true, true, failure, entries);
        }

        int invocationCount() {
            return entries.size();
        }

        int uniqueCommandCount() {
            Set<Integer> ids = new HashSet<>();
            for (Entry e : entries) {
                ids.add(e.commandId);
            }
            return ids.size();
        }

        List<Entry> riskyEntries() {
            List<Entry> out = new ArrayList<>();
            for (Entry e : entries) {
                if (e.risky()) {
                    out.add(e);
                }
            }
            sortEntries(out);
            return out;
        }

        List<Entry> publicDisclosure() {
            List<Entry> out = new ArrayList<>();
            for (Entry e : entries) {
                if (DISCLOSURE.contains(e.label) && e.publicish()) {
                    out.add(e);
                }
            }
            sortEntries(out);
            return out;
        }

        List<Entry> namespaceOpReachable() {
            List<Entry> out = new ArrayList<>();
            for (Entry e : entries) {
                if (e.namespaced && OP_NAMESPACE.contains(e.label)) {
                    out.add(e);
                }
            }
            sortEntries(out);
            return out;
        }

        List<Entry> pluginManagerCommands() {
            List<Entry> out = new ArrayList<>();
            for (Entry e : entries) {
                if (PLUGIN_MANAGER.contains(e.label) || looksLikePluginManager(e.owner)) {
                    out.add(e);
                }
            }
            sortEntries(out);
            return out;
        }

        List<Entry> dangerousDefaults() {
            List<Entry> out = new ArrayList<>();
            for (Entry e : entries) {
                if (DANGEROUS_DEFAULT.contains(e.label) && e.publicish()) {
                    out.add(e);
                }
            }
            sortEntries(out);
            return out;
        }

        List<Entry> lifecycleExposed() {
            List<Entry> out = new ArrayList<>();
            for (Entry e : entries) {
                if (LIFECYCLE.contains(e.label) && e.publicish()) {
                    out.add(e);
                }
            }
            sortEntries(out);
            return out;
        }

        List<Entry> tabCompleteTargets() {
            List<Entry> out = new ArrayList<>();
            for (Entry e : entries) {
                if (SENSITIVE.contains(e.label)) {
                    out.add(e);
                }
            }
            sortEntries(out);
            return out;
        }

        List<Duplicate> riskyDuplicates() {
            Map<String, List<Entry>> byLabel = new HashMap<>();
            for (Entry e : entries) {
                if (!SENSITIVE.contains(e.label)) {
                    continue;
                }
                List<Entry> list = byLabel.get(e.label);
                if (list == null) {
                    list = new ArrayList<>();
                    byLabel.put(e.label, list);
                }
                list.add(e);
            }
            List<Duplicate> out = new ArrayList<>();
            for (Map.Entry<String, List<Entry>> e : byLabel.entrySet()) {
                Set<Integer> ids = new HashSet<>();
                for (Entry ce : e.getValue()) {
                    ids.add(ce.commandId);
                }
                if (ids.size() > 1) {
                    sortEntries(e.getValue());
                    out.add(new Duplicate(e.getKey(), e.getValue()));
                }
            }
            out.sort(new Comparator<Duplicate>() {
                public int compare(Duplicate a, Duplicate b) {
                    return a.label.compareTo(b.label);
                }
            });
            return out;
        }
    }

    Result scan() {
        try {
            return fromCommandMap();
        } catch (Throwable liveError) {
            String failure = liveError.getClass().getSimpleName() + ": " + clean(liveError.getMessage());
            try {
                Result fallback = fromPluginYml();
                if (!fallback.entries.isEmpty()) {
                    return Result.partial(failure, fallback.entries);
                }
            } catch (Throwable ignored) {
            }
            return Result.unavailable(failure);
        }
    }

    private Result fromCommandMap() throws Exception {
        Map<?, ?> known = knownCommands();
        List<Entry> entries = new ArrayList<>();
        List<Map.Entry<?, ?>> snapshot = new ArrayList<>();
        for (Map.Entry<?, ?> raw : known.entrySet()) {
            snapshot.add(raw);
        }
        for (Map.Entry<?, ?> raw : snapshot) {
            if (!(raw.getKey() instanceof String) || !(raw.getValue() instanceof Command)) {
                continue;
            }
            String key = ((String) raw.getKey()).trim().toLowerCase(Locale.ROOT);
            if (key.isEmpty()) {
                continue;
            }
            entries.add(new Entry(key, (Command) raw.getValue()));
        }
        sortEntries(entries);
        return new Result(true, false, "", entries);
    }

    private Result fromPluginYml() {
        List<Entry> entries = new ArrayList<>();
        int id = 1;
        for (Plugin p : Bukkit.getPluginManager().getPlugins()) {
            Map<String, Map<String, Object>> commands = p.getDescription().getCommands();
            if (commands == null) {
                continue;
            }
            for (Map.Entry<String, Map<String, Object>> c : commands.entrySet()) {
                String key = clean(c.getKey()).toLowerCase(Locale.ROOT);
                if (key.isEmpty()) {
                    continue;
                }
                Map<String, Object> meta = c.getValue();
                Object rawPermission = meta == null ? null : meta.get("permission");
                String permission = rawPermission == null ? "" : clean(String.valueOf(rawPermission));
                entries.add(new Entry(key, p.getName(), permission, id));
                for (String alias : aliases(meta)) {
                    entries.add(new Entry(alias, p.getName(), permission, id));
                }
                id++;
            }
        }
        sortEntries(entries);
        return new Result(true, false, "", entries);
    }

    private Map<?, ?> knownCommands() throws Exception {
        Object server = Bukkit.getServer();
        Method getCommandMap = server.getClass().getMethod("getCommandMap");
        Object commandMap = getCommandMap.invoke(server);
        Method getKnownCommands = commandMap.getClass().getDeclaredMethod("getKnownCommands");
        getKnownCommands.setAccessible(true);
        Object raw = getKnownCommands.invoke(commandMap);
        if (!(raw instanceof Map)) {
            throw new IllegalStateException("knownCommands is not a map");
        }
        return (Map<?, ?>) raw;
    }

    private static String owner(Command command, String namespace) {
        if (command instanceof PluginIdentifiableCommand) {
            try {
                return ((PluginIdentifiableCommand) command).getPlugin().getName();
            } catch (Throwable ignored) {
                return "plugin";
            }
        }
        if (!namespace.isEmpty()) {
            return namespace;
        }
        String cn = command.getClass().getName();
        int dot = cn.lastIndexOf('.');
        return dot < 0 ? cn : cn.substring(dot + 1);
    }

    private static String declaredDefault(String permission) {
        if (permission.isEmpty()) {
            return "";
        }
        try {
            Permission p = Bukkit.getPluginManager().getPermission(permission);
            return p == null || p.getDefault() == null ? "" : p.getDefault().name();
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static boolean looksLikePluginManager(String value) {
        String v = value == null ? "" : value.toLowerCase(Locale.ROOT);
        return v.contains("plugman") || v.contains("pluginmanager") || v.contains("serverutils");
    }

    private static List<String> aliases(Map<String, Object> meta) {
        if (meta == null) {
            return Collections.emptyList();
        }
        Object raw = meta.get("aliases");
        List<String> out = new ArrayList<>();
        if (raw instanceof String) {
            String s = ((String) raw).trim().toLowerCase(Locale.ROOT);
            if (!s.isEmpty()) {
                out.add(s);
            }
        } else if (raw instanceof Iterable) {
            for (Object o : (Iterable<?>) raw) {
                String s = clean(String.valueOf(o)).toLowerCase(Locale.ROOT);
                if (!s.isEmpty()) {
                    out.add(s);
                }
            }
        }
        return out;
    }

    private static void sortEntries(List<Entry> entries) {
        entries.sort(new Comparator<Entry>() {
            public int compare(Entry a, Entry b) {
                int k = a.key.compareTo(b.key);
                return k != 0 ? k : a.owner.compareTo(b.owner);
            }
        });
    }

    static String examples(List<Entry> entries, int max) {
        List<String> parts = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (Entry e : entries) {
            String p = e.key + " (" + e.owner + ")";
            if (seen.add(p)) {
                parts.add(p);
            }
            if (parts.size() >= max) {
                break;
            }
        }
        if (seen.size() < entries.size()) {
            parts.add("+" + (entries.size() - seen.size()) + " more");
        }
        return String.join(", ", parts);
    }

    static String duplicateExamples(List<Duplicate> duplicates, int max) {
        List<String> parts = new ArrayList<>();
        int shown = 0;
        for (Duplicate d : duplicates) {
            if (shown++ >= max) {
                break;
            }
            parts.add(d.label);
        }
        if (duplicates.size() > max) {
            parts.add("+" + (duplicates.size() - max) + " more");
        }
        return String.join(", ", parts);
    }

    private static String clean(String s) {
        return s == null ? "" : s.replace('\n', ' ').replace('\r', ' ').trim();
    }

    private static Set<String> set(String... values) {
        return new HashSet<>(Arrays.asList(values));
    }
}
