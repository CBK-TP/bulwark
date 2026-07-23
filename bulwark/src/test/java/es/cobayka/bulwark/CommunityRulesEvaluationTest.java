package es.cobayka.bulwark;

import org.bukkit.configuration.file.YamlConfiguration;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class CommunityRulesEvaluationTest {

    @Test
    public void tritonRuleRequiresVulnerableVersionAndBungeecordMode() {
        CommunityRules rules = bundled();
        YamlConfiguration cfg = new YamlConfiguration();
        cfg.set("bungeecord", true);

        assertTrue(contains(evaluate(rules, items(item("plugin", "Bukkit", "Triton", "3.8.3",
                "plugins/Triton.jar")), yaml("plugins/Triton/config.yml", cfg)),
                "community.plugin.triton.console-command-ghsa-8vj5-jccf-q25r"));

        cfg.set("bungeecord", false);
        assertFalse(contains(evaluate(rules, items(item("plugin", "Bukkit", "Triton", "3.8.3",
                "plugins/Triton.jar")), yaml("plugins/Triton/config.yml", cfg)),
                "community.plugin.triton.console-command-ghsa-8vj5-jccf-q25r"));
    }

    @Test
    public void unknownVersionDoesNotTriggerHighVersionAdvisory() {
        CommunityRules rules = bundled();

        assertFalse(contains(evaluate(rules, items(item("mod", "Fabric", "CC-Tweaked", "${version}",
                "mods/cc-tweaked.jar")), Collections.<String, YamlConfiguration>emptyMap()),
                "community.mod.cc-tweaked-imds-ssrf-ghsa-7p4w-mv69-2wm2"));
    }

    @Test
    public void versionUnknownInfoRuleMatchesOnlyUnknownVersions() {
        CommunityRules rules = load(
                "ruleset:\n" +
                        "  id: test\n" +
                        "  version: 1\n" +
                        "rules:\n" +
                        "  - id: community.test.version-unknown\n" +
                        "    severity: info\n" +
                        "    title: Test\n" +
                        "    detail: Detail\n" +
                        "    fix: Fix\n" +
                        "    when:\n" +
                        "      artifact:\n" +
                        "        name: CC-Tweaked\n" +
                        "        type: mod\n" +
                        "        version:\n" +
                        "          versionUnknown: true\n");

        assertTrue(contains(evaluate(rules, items(item("mod", "Fabric", "CC-Tweaked", "",
                "mods/cc-tweaked.jar")), Collections.<String, YamlConfiguration>emptyMap()),
                "community.test.version-unknown"));
        assertFalse(contains(evaluate(rules, items(item("mod", "Fabric", "CC-Tweaked", "1.106.0",
                "mods/cc-tweaked.jar")), Collections.<String, YamlConfiguration>emptyMap()),
                "community.test.version-unknown"));
    }

    @Test
    public void evidenceIsRedactedBeforeFindingOutput() {
        CommunityRules rules = bundled();
        YamlConfiguration cfg = new YamlConfiguration();
        cfg.set("bungeecord", true);

        List<Finding> findings = evaluate(rules, items(item("plugin", "Bukkit", "Triton", "3.8.3",
                "plugins/Triton.jar token=abcdef1234567890abcdef1234567890")), yaml("plugins/Triton/config.yml", cfg));

        Finding triton = finding(findings, "community.plugin.triton.console-command-ghsa-8vj5-jccf-q25r");
        assertFalse(triton.detail.contains("abcdef1234567890abcdef1234567890"));
    }

    @Test
    public void rangeFieldsInOneBlockAreAnded() {
        CommunityRules rules = load(
                "ruleset:\n" +
                        "  id: test\n" +
                        "  version: 1\n" +
                        "rules:\n" +
                        "  - id: community.test.interval\n" +
                        "    severity: info\n" +
                        "    title: Test\n" +
                        "    detail: Detail\n" +
                        "    fix: Fix\n" +
                        "    when:\n" +
                        "      artifact:\n" +
                        "        name: TestMod\n" +
                        "        type: mod\n" +
                        "        version:\n" +
                        "          gte: \"1.2.0\"\n" +
                        "          lt: \"1.8.3\"\n");

        assertTrue(contains(evaluate(rules, items(item("mod", "Forge", "TestMod", "1.8.2",
                "mods/TestMod.jar")), Collections.<String, YamlConfiguration>emptyMap()), "community.test.interval"));
        assertFalse(contains(evaluate(rules, items(item("mod", "Forge", "TestMod", "9.9.9",
                "mods/TestMod.jar")), Collections.<String, YamlConfiguration>emptyMap()), "community.test.interval"));
    }

    @Test
    public void unusableMetadataFallsBackToJarFileVersion() {
        CommunityRules rules = load(
                "ruleset:\n" +
                        "  id: test\n" +
                        "  version: 1\n" +
                        "rules:\n" +
                        "  - id: community.test.fallback\n" +
                        "    severity: high\n" +
                        "    title: Test\n" +
                        "    detail: Detail\n" +
                        "    fix: Fix\n" +
                        "    when:\n" +
                        "      artifact:\n" +
                        "        name: IntegratedScripting\n" +
                        "        type: mod\n" +
                        "        version:\n" +
                        "          prefix: \"1.20.1-\"\n" +
                        "          range: \"<= 1.20.1-1.0.11\"\n");

        List<Finding> findings = evaluate(rules, items(item("mod", "Forge", "IntegratedScripting", "${file.jarVersion}",
                "mods/IntegratedScripting-1.20.1-1.0.11.jar")), Collections.<String, YamlConfiguration>emptyMap());
        Finding fallback = finding(findings, "community.test.fallback");
        assertEquals(Severity.INFO, fallback.severity);
        assertTrue(fallback.detail.contains("Possibly affected - verify manually"));
        assertTrue(fallback.detail.contains("version source: jar filename"));

        assertFalse(contains(evaluate(rules, items(item("mod", "Forge", "IntegratedScripting", "${file.jarVersion}",
                "mods/IntegratedScripting-1.20.1-1.0.13.jar")), Collections.<String, YamlConfiguration>emptyMap()),
                "community.test.fallback"));
    }

    @Test
    public void disabledJarDoesNotTriggerCommunityFinding() {
        CommunityRules rules = load(
                "ruleset:\n" +
                        "  id: test\n" +
                        "  version: 1\n" +
                        "rules:\n" +
                        "  - id: community.test.disabled\n" +
                        "    severity: high\n" +
                        "    title: Test\n" +
                        "    detail: Detail\n" +
                        "    fix: Fix\n" +
                        "    when:\n" +
                        "      artifact:\n" +
                        "        name: McWebserver\n" +
                        "        type: mod\n" +
                        "        version:\n" +
                        "          range: \"<= 0.1.2.1\"\n");

        assertFalse(contains(evaluate(rules, items(new MinecraftInventory.Item("mod", "Fabric", "McWebserver",
                "0.1.2.1", "mods/McWebserver.jar.disabled", "", 0, Arrays.asList("disabled"))),
                Collections.<String, YamlConfiguration>emptyMap()),
                "community.test.disabled"));
    }

    @Test
    public void artifactEvidenceKeepsFourComponentVersions() {
        CommunityRules rules = openComputersRule();
        List<Finding> findings = evaluate(rules, items(item("mod", "Forge", "OpenComputers", "1.7.5.192",
                "mods/OpenComputers.jar")), Collections.<String, YamlConfiguration>emptyMap());

        Finding oc = finding(findings, "community.test.opencomputers");
        assertTrue(oc.detail.contains("1.7.5.192"));
        assertFalse(oc.detail.contains("1.7.5.x"));
    }

    @Test
    public void allEvidenceKeepsArtifactFourComponentVersions() {
        CommunityRules rules = load(
                "ruleset:\n" +
                        "  id: test\n" +
                        "  version: 1\n" +
                        "rules:\n" +
                        "  - id: community.test.all-artifact-version\n" +
                        "    severity: info\n" +
                        "    title: Test\n" +
                        "    detail: Detail\n" +
                        "    fix: Fix\n" +
                        "    when:\n" +
                        "      all:\n" +
                        "        - artifact:\n" +
                        "            name: OpenComputers\n" +
                        "            type: mod\n" +
                        "            version:\n" +
                        "              range: \">= 1.2.0 < 1.8.3\"\n" +
                        "        - serverProperty:\n" +
                        "            key: online-mode\n" +
                        "            equals: \"true\"\n");
        Properties props = new Properties();
        props.setProperty("online-mode", "true");

        List<Finding> findings = evaluate(rules, items(item("mod", "Forge", "OpenComputers", "1.7.5.192",
                "mods/OpenComputers.jar")), props, Collections.<String, YamlConfiguration>emptyMap());

        Finding finding = finding(findings, "community.test.all-artifact-version");
        assertTrue(finding.detail.contains("1.7.5.192"));
        assertFalse(finding.detail.contains("1.7.5.x"));
    }

    @Test
    public void notOverUnknownVersionCapsSeverity() {
        CommunityRules rules = load(
                "ruleset:\n" +
                        "  id: test\n" +
                        "  version: 1\n" +
                        "rules:\n" +
                        "  - id: community.test.not-unknown\n" +
                        "    severity: high\n" +
                        "    title: Test\n" +
                        "    detail: Detail\n" +
                        "    fix: Fix\n" +
                        "    when:\n" +
                        "      not:\n" +
                        "        artifact:\n" +
                        "          name: TestMod\n" +
                        "          type: mod\n" +
                        "          version:\n" +
                        "            range: \"< 1.0.0\"\n");

        Finding finding = finding(evaluate(rules, items(item("mod", "Forge", "TestMod", "${file.jarVersion}",
                "mods/TestMod.jar")), Collections.<String, YamlConfiguration>emptyMap()), "community.test.not-unknown");

        assertEquals(Severity.INFO, finding.severity);
        assertTrue(finding.detail.contains("Possibly affected - verify manually"));
    }

    private static CommunityRules bundled() {
        InputStream in = CommunityRulesEvaluationTest.class.getClassLoader()
                .getResourceAsStream("rules/community-rules.yml");
        return CommunityRules.load(in, "rules/community-rules.yml");
    }

    private static CommunityRules load(String yaml) {
        return CommunityRules.load(new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)), "test.yml");
    }

    private static CommunityRules openComputersRule() {
        return load(
                "ruleset:\n" +
                        "  id: test\n" +
                        "  version: 1\n" +
                        "rules:\n" +
                        "  - id: community.test.opencomputers\n" +
                        "    severity: high\n" +
                        "    title: Test\n" +
                        "    detail: Detail\n" +
                        "    fix: Fix\n" +
                        "    when:\n" +
                        "      artifact:\n" +
                        "        name: OpenComputers\n" +
                        "        type: mod\n" +
                        "        version:\n" +
                        "          range: \">= 1.2.0 < 1.8.3\"\n");
    }

    private static List<Finding> evaluate(CommunityRules rules, List<MinecraftInventory.Item> items,
                                          Map<String, YamlConfiguration> yaml) {
        return evaluate(rules, items, new Properties(), yaml);
    }

    private static List<Finding> evaluate(CommunityRules rules, List<MinecraftInventory.Item> items, Properties props,
                                          Map<String, YamlConfiguration> yaml) {
        CommunityRules.Context ctx = new CommunityRules.Context(new MinecraftInventory.Result(items), props,
                "Paper", "Bukkit plugin loader", "1.20.1", "standard", null, null, yaml);
        return rules.evaluate(ctx).findings;
    }

    private static Finding finding(List<Finding> findings, String id) {
        for (Finding f : findings) {
            if (id.equals(f.id)) {
                return f;
            }
        }
        throw new AssertionError("missing finding " + id);
    }

    private static boolean contains(List<Finding> findings, String id) {
        for (Finding f : findings) {
            if (id.equals(f.id)) {
                return true;
            }
        }
        return false;
    }

    private static List<MinecraftInventory.Item> items(MinecraftInventory.Item item) {
        return Arrays.asList(item);
    }

    private static MinecraftInventory.Item item(String type, String loader, String name, String version, String path) {
        return new MinecraftInventory.Item(type, loader, name, version, path, "", 0, Collections.<String>emptyList());
    }

    private static Map<String, YamlConfiguration> yaml(String path, YamlConfiguration cfg) {
        Map<String, YamlConfiguration> map = new HashMap<>();
        map.put(path, cfg);
        return map;
    }
}
