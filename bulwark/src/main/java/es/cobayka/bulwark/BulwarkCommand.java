package es.cobayka.bulwark;

import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/** /bulwark - run an audit, see the full list, save a report, or reload the config. */
final class BulwarkCommand implements CommandExecutor, TabCompleter {

    private final BulwarkPlugin plugin;

    BulwarkCommand(BulwarkPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!sender.hasPermission("bulwark.admin")) {
            sender.sendMessage(ChatColor.RED + Messages.t("cmd.no-permission", "You don't have permission to do that."));
            return true;
        }

        String sub = args.length == 0 ? "run" : args[0].toLowerCase();
        switch (sub) {
            case "run":
            case "scan":
            case "status":
                plugin.report().send(sender, plugin.audit(), false);
                return true;
            case "full":
                plugin.report().send(sender, plugin.audit(), true);
                return true;
            case "report": {
                String stamp = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss").format(new Date());
                AuditEngine.Result result = plugin.audit();
                File txt = plugin.report().writeFile(result, stamp);
                File md = plugin.report().writeMarkdown(result, stamp);
                if (txt != null) {
                    sender.sendMessage(ChatColor.GREEN + Messages.t("cmd.report-saved", "Report saved: {0}", ChatColor.GRAY + "plugins/Bulwark/" + txt.getName()));
                    if (md != null) {
                        sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.report-md", "Shareable Markdown: ") + ChatColor.WHITE + "plugins/Bulwark/" + md.getName());
                    }
                } else {
                    sender.sendMessage(ChatColor.RED + Messages.t("cmd.report-fail", "Could not write the report file."));
                }
                return true;
            }
            case "badge": {
                AuditEngine.Result result = plugin.audit();
                File svg = plugin.report().writeBadge(result);
                if (svg != null) {
                    sender.sendMessage(ChatColor.GREEN + Messages.t("cmd.badge-saved", "Security badge saved: {0}", ChatColor.GRAY + "plugins/Bulwark/badge.svg"));
                } else {
                    sender.sendMessage(ChatColor.RED + Messages.t("cmd.badge-fail", "Could not write the badge file."));
                }
                sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.badge-markdown", "Markdown: {0}", ChatColor.WHITE + Badge.markdown(result)));
                sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.badge-bbcode", "BBCode: {0}", ChatColor.WHITE + Badge.bbcode(result)));
                return true;
            }
            case "consent":
                return doConsent(sender, args);
            case "trust":
                return doTrust(sender, args);
            case "inventory":
            case "surface":
                return doInventory(sender, args);
            case "commands":
                return doCommands(sender, args);
            case "posture":
            case "profile":
                return doPosture(sender);
            case "artifact":
                return doArtifact(sender, args);
            case "reload":
                plugin.reloadRuntime();
                sender.sendMessage(ChatColor.GREEN + Messages.t("cmd.reloaded", "Bulwark config reloaded."));
                return true;
            default:
                sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.usage-free", "Usage: /{0} <run|full|report|badge|consent|trust|inventory|commands|posture|artifact|reload>", label));
                return true;
        }
    }

    private boolean doTrust(CommandSender sender, String[] args) {
        if (!plugin.consented()) {
            sender.sendMessage(ChatColor.YELLOW + Messages.t("cmd.scan-not-authorized", "Scanning isn't authorized yet."));
            sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.scan-run-consent", "Run {0} first.", ChatColor.WHITE + "/bulwark consent" + ChatColor.GRAY));
            return true;
        }
        PluginTrust trust = plugin.trust();
        String action = args.length > 1 ? args[1].toLowerCase() : "status";
        if (action.equals("baseline") || action.equals("accept") || action.equals("reset")) {
            int n = trust.save();
            if (n < 0) {
                sender.sendMessage(ChatColor.RED + Messages.t("cmd.trust-save-failed", "Could not save the trusted plugin baseline."));
            } else {
                sender.sendMessage(ChatColor.GREEN + Messages.t("cmd.trust-saved", "Trusted plugin baseline saved: {0} jar(s).", n));
            }
            return true;
        }
        if (!trust.hasBaseline()) {
            sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.trust-empty", "No trusted plugin baseline yet."));
            sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.trust-empty-hint", "Current plugin jars visible: {0}. Run {1} after checking them.",
                    trust.currentCount(), ChatColor.WHITE + "/bulwark trust baseline" + ChatColor.GRAY));
            return true;
        }
        List<PluginTrust.Delta> delta = trust.diff();
        if (delta.isEmpty()) {
            sender.sendMessage(ChatColor.GREEN + Messages.t("cmd.trust-ok", "Plugin jars match the trusted baseline."));
            return true;
        }
        sender.sendMessage(ChatColor.RED + Messages.t("cmd.trust-drift", "Plugin jar changes since baseline: {0}", delta.size()));
        int shown = 0;
        for (PluginTrust.Delta d : delta) {
            if (shown++ >= 12) {
                sender.sendMessage(ChatColor.DARK_GRAY + Messages.t("cmd.trust-more", "...and {0} more.", delta.size() - 12));
                break;
            }
            sender.sendMessage(ChatColor.GRAY + "  " + trustLine(d));
        }
        return true;
    }

    private boolean doCommands(CommandSender sender, String[] args) {
        if (!plugin.consented()) {
            sender.sendMessage(ChatColor.YELLOW + Messages.t("cmd.scan-not-authorized", "Scanning isn't authorized yet."));
            sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.scan-run-consent", "Run {0} first.", ChatColor.WHITE + "/bulwark consent" + ChatColor.GRAY));
            return true;
        }
        String view = args.length > 1 ? args[1].toLowerCase() : "summary";
        CommandSurface.Result surface = plugin.commandSurface().scan();
        if (!surface.available) {
            sender.sendMessage(ChatColor.YELLOW + Messages.t("cmd.commands-unavailable", "Command surface unavailable: {0}", surface.failure));
            return true;
        }
        if (surface.partial) {
            sender.sendMessage(ChatColor.YELLOW + Messages.t("cmd.commands-partial", "Live command map unavailable; showing partial plugin.yml metadata: {0}", surface.failure));
        }
        List<CommandSurface.Entry> risky = surface.riskyEntries();
        List<CommandSurface.Duplicate> duplicates = surface.riskyDuplicates();
        sender.sendMessage(ChatColor.AQUA + Messages.t("cmd.commands-header", "Command surface: {0} invocation(s), {1} unique command(s), {2} risky label(s), {3} duplicate sensitive label(s)",
                surface.invocationCount(), surface.uniqueCommandCount(), risky.size(), duplicates.size()));
        if ("summary".equals(view)) {
            printEntries(sender, risky, 10);
            if (!duplicates.isEmpty()) {
                sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.commands-duplicates-short", "Duplicate sensitive labels: {0}", CommandSurface.duplicateExamples(duplicates, 8)));
            }
            sender.sendMessage(ChatColor.DARK_GRAY + Messages.t("cmd.commands-hint", "Views: {0}", ChatColor.WHITE + "summary|risky|duplicates|all" + ChatColor.DARK_GRAY));
            return true;
        }
        if ("risky".equals(view)) {
            printEntries(sender, risky, 60);
            return true;
        }
        if ("duplicates".equals(view)) {
            if (duplicates.isEmpty()) {
                sender.sendMessage(ChatColor.GREEN + Messages.t("cmd.commands-no-duplicates", "No duplicate sensitive command labels found."));
                return true;
            }
            int shown = 0;
            for (CommandSurface.Duplicate d : duplicates) {
                if (shown++ >= 40) {
                    sender.sendMessage(ChatColor.DARK_GRAY + Messages.t("cmd.commands-more", "...and {0} more.", duplicates.size() - 40));
                    break;
                }
                sender.sendMessage(ChatColor.GRAY + "  " + d.line());
            }
            return true;
        }
        if ("all".equals(view)) {
            printEntries(sender, surface.entries, 120);
            return true;
        }
        sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.commands-usage", "Usage: /bulwark commands [summary|risky|duplicates|all]"));
        return true;
    }

    private boolean doPosture(CommandSender sender) {
        if (!plugin.consented()) {
            sender.sendMessage(ChatColor.YELLOW + Messages.t("cmd.scan-not-authorized", "Scanning isn't authorized yet."));
            sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.scan-run-consent", "Run {0} first.", ChatColor.WHITE + "/bulwark consent" + ChatColor.GRAY));
            return true;
        }
        AuditEngine.Result result = plugin.audit();
        sender.sendMessage(ChatColor.AQUA + Messages.t("cmd.posture-header", "Security posture: {0}", result.posture));
        sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.runtime-header", "Runtime: {0}", result.profile));
        int shown = 0;
        for (Finding f : result.findings) {
            if (!postureFinding(f)) {
                continue;
            }
            if (shown++ >= 12) {
                sender.sendMessage(ChatColor.DARK_GRAY + Messages.t("cmd.posture-more", "...and {0} more posture finding(s).", postureCount(result.findings) - 12));
                break;
            }
            sender.sendMessage(f.severity.color + "  [" + f.severity.label + "] " + f.title);
            sender.sendMessage(ChatColor.GRAY + "    " + f.fix);
        }
        if (shown == 0) {
            sender.sendMessage(ChatColor.GREEN + Messages.t("cmd.posture-empty", "No profile-specific posture findings are active."));
        }
        return true;
    }

    private boolean doInventory(CommandSender sender, String[] args) {
        if (!plugin.consented()) {
            sender.sendMessage(ChatColor.YELLOW + Messages.t("cmd.scan-not-authorized", "Scanning isn't authorized yet."));
            sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.scan-run-consent", "Run {0} first.", ChatColor.WHITE + "/bulwark consent" + ChatColor.GRAY));
            return true;
        }
        String filter = args.length > 1 ? args[1].toLowerCase() : "flags";
        MinecraftInventory.Result inv = plugin.inventory().scan();
        sender.sendMessage(ChatColor.AQUA + Messages.t("cmd.inventory-header",
                "Minecraft inventory: {0} plugin(s), {1} mod(s), {2} datapack(s), {3} resource pack(s), {4} root jar(s), {5} startup file(s)",
                inv.count("plugin"), inv.count("mod") + inv.count("hybrid"), inv.count("datapack"),
                inv.count("resource-pack"), inv.count("server-jar"), inv.count("startup")));
        sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.inventory-flagged", "Flagged items: {0}", inv.flagged()));
        List<MinecraftInventory.Item> selected = new ArrayList<>();
        for (MinecraftInventory.Item i : inv.items) {
            if (inventoryMatch(i, filter)) {
                selected.add(i);
            }
        }
        if (selected.isEmpty()) {
            sender.sendMessage(ChatColor.GREEN + Messages.t("cmd.inventory-empty", "No inventory items matched this view."));
            return true;
        }
        int limit = "all".equals(filter) ? 60 : 30;
        int shown = 0;
        for (MinecraftInventory.Item i : selected) {
            if (shown++ >= limit) {
                sender.sendMessage(ChatColor.DARK_GRAY + Messages.t("cmd.inventory-more", "...and {0} more.", selected.size() - limit));
                break;
            }
            sender.sendMessage((i.flagged() ? ChatColor.YELLOW : ChatColor.GRAY) + "  " + inventoryLine(i));
        }
        if ("flags".equals(filter)) {
            sender.sendMessage(ChatColor.DARK_GRAY + Messages.t("cmd.inventory-hint", "Use {0} for the full inventory.", ChatColor.WHITE + "/bulwark inventory all" + ChatColor.DARK_GRAY));
        }
        return true;
    }

    private boolean doArtifact(CommandSender sender, String[] args) {
        if (!plugin.consented()) {
            sender.sendMessage(ChatColor.YELLOW + Messages.t("cmd.scan-not-authorized", "Scanning isn't authorized yet."));
            sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.scan-run-consent", "Run {0} first.", ChatColor.WHITE + "/bulwark consent" + ChatColor.GRAY));
            return true;
        }
        if (args.length < 3) {
            sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.artifact-usage", "Usage: /bulwark artifact <info|configs|check> <name|path>"));
            return true;
        }
        String action = args[1].toLowerCase();
        String token = joinArgs(args, 2);
        if ("info".equals(action)) {
            MinecraftInventory.Item item = plugin.artifacts().item(token);
            if (item == null) {
                sender.sendMessage(ChatColor.RED + Messages.t("cmd.artifact-not-found", "Artifact not found: {0}", token));
                return true;
            }
            sender.sendMessage(ChatColor.AQUA + Messages.t("cmd.artifact-info", "Artifact: {0}", item.name));
            sender.sendMessage(ChatColor.GRAY + "  " + inventoryLine(item));
            return true;
        }
        if ("configs".equals(action)) {
            List<File> configs = plugin.artifacts().configs(token);
            if (configs.isEmpty()) {
                sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.artifact-no-configs", "No config files found for {0}.", token));
                return true;
            }
            sender.sendMessage(ChatColor.AQUA + Messages.t("cmd.artifact-configs", "Config files for {0}:", token));
            for (File f : configs) {
                sender.sendMessage(ChatColor.GRAY + "  " + f.getParentFile().getName() + "/" + f.getName() + " (" + f.length() + " bytes)");
            }
            return true;
        }
        if ("check".equals(action)) {
            if (!plugin.getConfig().getBoolean("advisory.enabled", false)) {
                sender.sendMessage(ChatColor.YELLOW + Messages.t("cmd.artifact-advisory-off", "External advisory checks are off. Set advisory.enabled=true, then /bulwark reload."));
                return true;
            }
            MinecraftInventory.Item item = plugin.artifacts().item(token);
            if (item == null) {
                sender.sendMessage(ChatColor.RED + Messages.t("cmd.artifact-not-found", "Artifact not found: {0}", token));
                return true;
            }
            sender.sendMessage(ChatColor.AQUA + Messages.t("cmd.artifact-check", "Advisory check for {0}:", item.name));
            for (String line : plugin.advisor().check(item)) {
                sender.sendMessage(ChatColor.GRAY + "  " + line);
            }
            return true;
        }
        sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.artifact-usage", "Usage: /bulwark artifact <info|configs|check> <name|path>"));
        return true;
    }

    /** Grants or revokes consent for scanning (a .consent marker in the data folder). */
    private boolean doConsent(CommandSender sender, String[] args) {
        File marker = new File(plugin.getDataFolder(), ".consent");
        String arg = args.length > 1 ? args[1].toLowerCase() : "on";
        boolean configOn = plugin.getConfig().getBoolean("scan-consent", false);
        if (arg.equals("off") || arg.equals("revoke") || arg.equals("false") || arg.equals("no")) {
            marker.delete();
            if (configOn) {
                sender.sendMessage(ChatColor.YELLOW + Messages.t("cmd.consent-removed-config", "Removed the consent marker, but scan-consent is still true in config.yml."));
                sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.consent-removed-hint", "Set it to false there (then /bulwark reload) to fully stop scanning."));
            } else {
                sender.sendMessage(ChatColor.GREEN + Messages.t("cmd.consent-off", "Scanning disabled. Bulwark won't read anything until you consent again."));
            }
            return true;
        }
        try {
            plugin.getDataFolder().mkdirs();
            if (!marker.exists()) {
                marker.createNewFile();
            }
            sender.sendMessage(ChatColor.GREEN + Messages.t("cmd.consent-on", "Scanning authorized."));
            sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.consent-on-detail", "Bulwark will read this server's config and the host settings (permissions, OS user, JVM) - read-only, nothing leaves this machine."));
            sender.sendMessage(ChatColor.GRAY + Messages.t("cmd.consent-on-run", "Run {0} to see your grade; revoke any time with {1}.",
                    ChatColor.WHITE + "/bulwark" + ChatColor.GRAY, ChatColor.WHITE + "/bulwark consent off" + ChatColor.GRAY));
        } catch (Exception ex) {
            sender.sendMessage(ChatColor.RED + Messages.t("cmd.consent-error", "[BW-602] Couldn't write the consent marker: {0}", ex.getMessage()));
        }
        return true;
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (args.length == 1 && sender.hasPermission("bulwark.admin")) {
            List<String> out = new ArrayList<>();
            for (String option : Arrays.asList("run", "full", "report", "badge", "consent", "trust", "inventory", "commands", "posture", "artifact", "reload", "help")) {
                if (option.startsWith(args[0].toLowerCase())) {
                    out.add(option);
                }
            }
            return out;
        }
        if (args.length == 2 && "trust".equalsIgnoreCase(args[0]) && sender.hasPermission("bulwark.admin")) {
            List<String> out = new ArrayList<>();
            for (String option : Arrays.asList("status", "baseline")) {
                if (option.startsWith(args[1].toLowerCase())) {
                    out.add(option);
                }
            }
            return out;
        }
        if (args.length == 2 && ("inventory".equalsIgnoreCase(args[0]) || "surface".equalsIgnoreCase(args[0])) && sender.hasPermission("bulwark.admin")) {
            List<String> out = new ArrayList<>();
            for (String option : Arrays.asList("flags", "all", "plugins", "mods", "datapacks", "packs", "jars", "startup")) {
                if (option.startsWith(args[1].toLowerCase())) {
                    out.add(option);
                }
            }
            return out;
        }
        if (args.length == 2 && "commands".equalsIgnoreCase(args[0]) && sender.hasPermission("bulwark.admin")) {
            List<String> out = new ArrayList<>();
            for (String option : Arrays.asList("summary", "risky", "duplicates", "all")) {
                if (option.startsWith(args[1].toLowerCase())) {
                    out.add(option);
                }
            }
            return out;
        }
        if (args.length == 2 && "artifact".equalsIgnoreCase(args[0]) && sender.hasPermission("bulwark.admin")) {
            List<String> out = new ArrayList<>();
            for (String option : Arrays.asList("info", "configs", "check")) {
                if (option.startsWith(args[1].toLowerCase())) {
                    out.add(option);
                }
            }
            return out;
        }
        if (args.length == 2 && "consent".equalsIgnoreCase(args[0]) && sender.hasPermission("bulwark.admin")) {
            List<String> out = new ArrayList<>();
            for (String option : Arrays.asList("on", "off")) {
                if (option.startsWith(args[1].toLowerCase())) {
                    out.add(option);
                }
            }
            return out;
        }
        return Collections.emptyList();
    }

    private static String trustLine(PluginTrust.Delta d) {
        String now = PluginTrust.shortHash(d.newHash);
        String old = PluginTrust.shortHash(d.oldHash);
        String hash = old.isEmpty() ? now : (now.isEmpty() ? old : old + " -> " + now);
        return d.type + " " + d.name + (hash.isEmpty() ? "" : " [" + hash + "]");
    }

    private static boolean inventoryMatch(MinecraftInventory.Item i, String filter) {
        if ("all".equals(filter)) {
            return true;
        }
        if ("plugins".equals(filter) || "plugin".equals(filter)) {
            return "plugin".equals(i.type);
        }
        if ("mods".equals(filter) || "mod".equals(filter)) {
            return "mod".equals(i.type) || "hybrid".equals(i.type);
        }
        if ("datapacks".equals(filter) || "datapack".equals(filter)) {
            return "datapack".equals(i.type);
        }
        if ("packs".equals(filter)) {
            return "resource-pack".equals(i.type);
        }
        if ("jars".equals(filter) || "jar".equals(filter)) {
            return i.jar();
        }
        if ("startup".equals(filter)) {
            return "startup".equals(i.type);
        }
        return i.flagged();
    }

    private static String inventoryLine(MinecraftInventory.Item i) {
        String ver = i.version.isEmpty() ? "" : " " + i.version;
        String hash = i.hash.isEmpty() ? "" : " #" + i.hash;
        String flags = i.flags.isEmpty() ? "" : " ! " + String.join("; ", i.flags);
        return i.type + "/" + i.loader + " " + i.name + ver + " - " + i.path + hash + flags;
    }

    private static void printEntries(CommandSender sender, List<CommandSurface.Entry> entries, int limit) {
        if (entries.isEmpty()) {
            sender.sendMessage(ChatColor.GREEN + Messages.t("cmd.commands-empty", "No command entries matched this view."));
            return;
        }
        int shown = 0;
        for (CommandSurface.Entry e : entries) {
            if (shown++ >= limit) {
                sender.sendMessage(ChatColor.DARK_GRAY + Messages.t("cmd.commands-more", "...and {0} more.", entries.size() - limit));
                break;
            }
            sender.sendMessage(ChatColor.GRAY + "  " + e.line());
        }
    }

    private static boolean postureFinding(Finding f) {
        return f.id.startsWith("posture-")
                || f.id.startsWith("profile-")
                || f.id.startsWith("proxy-backend-")
                || f.id.startsWith("anti-xray-")
                || f.id.startsWith("floodgate-")
                || f.id.startsWith("geyser-")
                || f.id.startsWith("loader-");
    }

    private static int postureCount(List<Finding> findings) {
        int count = 0;
        for (Finding f : findings) {
            if (postureFinding(f)) {
                count++;
            }
        }
        return count;
    }

    private static String joinArgs(String[] args, int start) {
        StringBuilder b = new StringBuilder();
        for (int i = start; i < args.length; i++) {
            if (b.length() > 0) {
                b.append(' ');
            }
            b.append(args[i]);
        }
        return b.toString();
    }
}
