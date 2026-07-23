package es.cobayka.bulwark;

import org.bukkit.command.PluginCommand;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;

/**
 * Bulwark - reads the server's own config and reports its security posture.
 * It only reads; it never changes anything.
 */
public final class BulwarkPlugin extends JavaPlugin {

    private ServerEnv env;
    private AuditEngine engine;
    private Report report;
    private UpdateChecker updates;
    private PluginTrust trust;
    private MinecraftInventory inventory;
    private ArtifactControl artifacts;
    private ArtifactAdvisor advisor;
    private CommandSurface commandSurface;
    private LogTail logTail;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        Messages.init(this, getConfig().getString("language", "en"));
        env = new ServerEnv(this);
        engine = new AuditEngine(this, env);
        report = new Report(this);
        trust = new PluginTrust(this, env);
        inventory = new MinecraftInventory(this, env);
        artifacts = new ArtifactControl(this, env);
        advisor = new ArtifactAdvisor(this, env);
        commandSurface = new CommandSurface(this);
        logTail = new LogTail(this, env);
        updates = new UpdateChecker(this, null, true); // free: console notice only
        updates.start();

        PluginCommand command = getCommand("bulwark");
        if (command != null) {
            BulwarkCommand handler = new BulwarkCommand(this);
            command.setExecutor(handler);
            command.setTabCompleter(handler);
        } else {
            getLogger().severe("[BW-001] " + Messages.t("plugin.command-missing", "The 'bulwark' command is missing from plugin.yml."));
        }

        if (getConfig().getBoolean("scan-on-start", true)) {
            AuditEngine.Result result = audit();
            if (!result.consented) {
                getLogger().info(Messages.t("plugin.not-consented-free",
                        "Bulwark is installed but hasn't scanned yet - run /bulwark consent to authorize the first scan."));
            } else {
                getLogger().info(report.summaryLine(result));
                if (result.grade >= 'C') {
                    getLogger().warning(Messages.t("plugin.needs-attention", "Security needs attention - run /bulwark for the details."));
                }
            }
        }
    }

    @Override
    public void onDisable() {
        if (updates != null) {
            updates.stop();
        }
    }

    void reloadRuntime() {
        reloadConfig();
        Messages.init(this, getConfig().getString("language", "en"));
        if (updates != null) {
            updates.stop();
        }
        updates = new UpdateChecker(this, null, true);
        updates.start();
    }

    File installedJarFile() {
        return getFile();
    }

    AuditEngine.Result audit() {
        return engine.run();
    }

    Report report() {
        return report;
    }

    boolean consented() {
        return engine.consented();
    }

    PluginTrust trust() {
        return trust;
    }

    MinecraftInventory inventory() {
        return inventory;
    }

    ArtifactControl artifacts() {
        return artifacts;
    }

    ArtifactAdvisor advisor() {
        return advisor;
    }

    CommandSurface commandSurface() {
        return commandSurface;
    }

    LogTail logTail() {
        return logTail;
    }
}
