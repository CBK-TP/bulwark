package es.cobayka.bulwark;

import org.bukkit.configuration.file.YamlConfiguration;
import org.junit.Test;

import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RuleFixtureTest {

    @Test
    public void bundledRulesLoadCleanly() {
        CommunityRules rules = bundled();

        assertEquals(4, rules.rules().size());
        assertEquals(4, rules.diagnostics.loaded);
        assertEquals(0, rules.diagnostics.skipped);
    }

    @Test
    public void everyBundledRuleHasVulnerableAndSafeFixture() {
        CommunityRules rules = bundled();
        for (Fixture fixture : fixtures()) {
            assertTrue("missing vulnerable match for " + fixture.id,
                    contains(evaluate(rules, fixture.vulnerable, fixture.vulnerableYaml), fixture.id));
            assertFalse("safe fixture matched " + fixture.id,
                    contains(evaluate(rules, fixture.safe, fixture.safeYaml), fixture.id));
        }
    }

    @Test
    public void ccTweakedNewestBranchDoesNotMatchOlderBranchRules() {
        CommunityRules rules = bundled();

        assertFalse(contains(evaluate(rules,
                item("mod", "Fabric", "CC-Tweaked", "1.21.1-1.115.1", "mods/cc-tweaked.jar"), noYaml()),
                "community.mod.cc-tweaked-imds-ssrf-ghsa-7p4w-mv69-2wm2"));
    }

    @Test
    public void parkedRulesAreNotLoadedByBundledRuleset() {
        CommunityRules rules = bundled();

        assertFalse(contains(evaluate(rules,
                item("mod", "Forge", "IntegratedScripting", "${file.jarVersion}",
                        "mods/IntegratedScripting-1.20.1-1.0.11.jar"), noYaml()),
                "community.mod.integratedscripting-rce-1-20-1-ghsa-2v5x-4823-hq77"));
        assertFalse(contains(evaluate(rules,
                item("mod", "Forge", "OpenComputers", "1.7.5.192",
                        "mods/OpenComputers-MC1.7.10-1.8.3.jar"), noYaml()),
                "community.mod.opencomputers-imds-ssrf-ghsa-vvfj-xh7c-j2cm"));
    }

    private static List<Fixture> fixtures() {
        YamlConfiguration tritonOn = new YamlConfiguration();
        tritonOn.set("bungeecord", true);

        return Arrays.asList(
                fixture("community.plugin.triton.console-command-ghsa-8vj5-jccf-q25r",
                        item("plugin", "Bukkit", "Triton", "3.8.3", "plugins/Triton-3.8.3.jar"), yaml(tritonOn),
                        item("plugin", "Bukkit", "Triton", "3.8.4", "plugins/Triton-3.8.4.jar"), yaml(tritonOn)),
                fixture("community.plugin.geyser-jwt-impersonation-cve-2021-39177",
                        item("plugin", "Bukkit", "Geyser", "1.4.1-SNAPSHOT", "plugins/Geyser-Spigot-1.4.1-SNAPSHOT.jar"), noYaml(),
                        item("plugin", "Bukkit", "Geyser", "1.4.2-SNAPSHOT", "plugins/Geyser-Spigot-1.4.2-SNAPSHOT.jar"), noYaml()),
                fixture("community.plugin.geyser-head-texture-ssrf-cve-2026-42188",
                        item("plugin", "Bukkit", "Geyser", "2.9.2-SNAPSHOT", "plugins/Geyser-Spigot-2.9.2-SNAPSHOT.jar"), noYaml(),
                        item("plugin", "Bukkit", "Geyser", "2.9.3-SNAPSHOT", "plugins/Geyser-Spigot-2.9.3-SNAPSHOT.jar"), noYaml()),
                fixture("community.mod.command-block-ide-function-write-cve-2024-48645",
                        item("mod", "Fabric", "Command Block IDE", "0.4.9+1.20.1", "mods/command-block-ide-0.4.9+1.20.1.jar"), noYaml(),
                        item("mod", "Fabric", "Command Block IDE", "0.4.10+1.20.1", "mods/command-block-ide-0.4.10+1.20.1.jar"), noYaml()));
    }

    private static CommunityRules bundled() {
        InputStream in = RuleFixtureTest.class.getClassLoader().getResourceAsStream("rules/community-rules.yml");
        return CommunityRules.load(in, "rules/community-rules.yml");
    }

    private static List<Finding> evaluate(CommunityRules rules, MinecraftInventory.Item item,
                                          Map<String, YamlConfiguration> yaml) {
        CommunityRules.Context ctx = new CommunityRules.Context(
                new MinecraftInventory.Result(Arrays.asList(item)), new Properties(),
                "Paper", "Bukkit plugin loader", "1.20.1", "standard", null, null, yaml);
        return rules.evaluate(ctx).findings;
    }

    private static boolean contains(List<Finding> findings, String id) {
        for (Finding f : findings) {
            if (id.equals(f.id)) {
                return true;
            }
        }
        return false;
    }

    private static Fixture fixture(String id, MinecraftInventory.Item vulnerable,
                                   Map<String, YamlConfiguration> vulnerableYaml,
                                   MinecraftInventory.Item safe,
                                   Map<String, YamlConfiguration> safeYaml) {
        return new Fixture(id, vulnerable, vulnerableYaml, safe, safeYaml);
    }

    private static MinecraftInventory.Item item(String type, String loader, String name, String version, String path) {
        return new MinecraftInventory.Item(type, loader, name, version, path, "", 0, Collections.<String>emptyList());
    }

    private static Map<String, YamlConfiguration> yaml(YamlConfiguration cfg) {
        Map<String, YamlConfiguration> map = new HashMap<>();
        map.put("plugins/Triton/config.yml", cfg);
        return map;
    }

    private static Map<String, YamlConfiguration> noYaml() {
        return Collections.emptyMap();
    }

    private static final class Fixture {
        final String id;
        final MinecraftInventory.Item vulnerable;
        final Map<String, YamlConfiguration> vulnerableYaml;
        final MinecraftInventory.Item safe;
        final Map<String, YamlConfiguration> safeYaml;

        Fixture(String id, MinecraftInventory.Item vulnerable, Map<String, YamlConfiguration> vulnerableYaml,
                MinecraftInventory.Item safe, Map<String, YamlConfiguration> safeYaml) {
            this.id = id;
            this.vulnerable = vulnerable;
            this.vulnerableYaml = vulnerableYaml;
            this.safe = safe;
            this.safeYaml = safeYaml;
        }
    }
}
