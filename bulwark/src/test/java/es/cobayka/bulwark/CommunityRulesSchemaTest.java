package es.cobayka.bulwark;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class CommunityRulesSchemaTest {

    @Test
    public void validMinimalRuleLoads() {
        CommunityRules rules = load(
                "ruleset:\n" +
                        "  id: test\n" +
                        "  version: 1\n" +
                        "  minEngine: 1\n" +
                        "rules:\n" +
                        "  - id: community.test.valid-rule\n" +
                        "    severity: info\n" +
                        "    title: Test\n" +
                        "    detail: Detail\n" +
                        "    fix: Fix\n" +
                        "    sources: [\"https://example.com/advisory\"]\n" +
                        "    when:\n" +
                        "      artifact:\n" +
                        "        name: TestMod\n" +
                        "        type: mod\n");

        assertEquals(1, rules.rules().size());
        assertEquals(1, rules.diagnostics.loaded);
        assertEquals(0, rules.diagnostics.skipped);
    }

    @Test
    public void forbiddenMatchersInsideRuleRowsAreSkipped() {
        CommunityRules rules = load(
                "ruleset:\n" +
                        "  id: test\n" +
                        "  version: 1\n" +
                        "  minEngine: 1\n" +
                        "rules:\n" +
                        "  - id: community.test.regex-rule\n" +
                        "    severity: info\n" +
                        "    title: Test\n" +
                        "    detail: Detail\n" +
                        "    fix: Fix\n" +
                        "    when:\n" +
                        "      artifact:\n" +
                        "        name: TestMod\n" +
                        "        type: mod\n" +
                        "        regex: \".*\"\n");

        assertEquals(0, rules.rules().size());
        assertEquals(1, rules.diagnostics.skipped);
        assertTrue(rules.diagnostics.summary().contains("forbidden executable matcher"));
    }

    @Test
    public void highSeverityCannotMatchUnknownVersions() {
        CommunityRules rules = load(
                "ruleset:\n" +
                        "  id: test\n" +
                        "  version: 1\n" +
                        "  minEngine: 1\n" +
                        "rules:\n" +
                        "  - id: community.test.unknown-high\n" +
                        "    severity: high\n" +
                        "    title: Test\n" +
                        "    detail: Detail\n" +
                        "    fix: Fix\n" +
                        "    when:\n" +
                        "      artifact:\n" +
                        "        name: TestMod\n" +
                        "        type: mod\n" +
                        "        version:\n" +
                        "          versionUnknown: true\n");

        assertEquals(0, rules.rules().size());
        assertEquals(1, rules.diagnostics.skipped);
        assertTrue(rules.diagnostics.summary().contains("versionUnknown"));
    }

    @Test
    public void unknownAliasCannotBypassVersionUnknownGuard() {
        CommunityRules rules = load(
                "ruleset:\n" +
                        "  id: test\n" +
                        "  version: 1\n" +
                        "  minEngine: 1\n" +
                        "rules:\n" +
                        "  - id: community.test.unknown-alias\n" +
                        "    severity: critical\n" +
                        "    title: Test\n" +
                        "    detail: Detail\n" +
                        "    fix: Fix\n" +
                        "    when:\n" +
                        "      artifact:\n" +
                        "        name: TestMod\n" +
                        "        type: mod\n" +
                        "        version:\n" +
                        "          unknown: true\n");

        assertEquals(0, rules.rules().size());
        assertEquals(1, rules.diagnostics.skipped);
        assertTrue(rules.diagnostics.summary().contains("missing version range"));
    }

    @Test
    public void versionBlockWithoutRangeIsRejected() {
        CommunityRules rules = load(
                "ruleset:\n" +
                        "  id: test\n" +
                        "  version: 1\n" +
                        "  minEngine: 1\n" +
                        "rules:\n" +
                        "  - id: community.test.prefix-only\n" +
                        "    severity: info\n" +
                        "    title: Test\n" +
                        "    detail: Detail\n" +
                        "    fix: Fix\n" +
                        "    when:\n" +
                        "      artifact:\n" +
                        "        name: TestMod\n" +
                        "        type: mod\n" +
                        "        version:\n" +
                        "          prefix: \"1.20.1-\"\n");

        assertEquals(0, rules.rules().size());
        assertEquals(1, rules.diagnostics.skipped);
        assertTrue(rules.diagnostics.summary().contains("missing version range"));
    }

    @Test
    public void nullVersionBlockIsRejected() {
        CommunityRules rules = load(
                "ruleset:\n" +
                        "  id: test\n" +
                        "  version: 1\n" +
                        "  minEngine: 1\n" +
                        "rules:\n" +
                        "  - id: community.test.null-version\n" +
                        "    severity: info\n" +
                        "    title: Test\n" +
                        "    detail: Detail\n" +
                        "    fix: Fix\n" +
                        "    when:\n" +
                        "      artifact:\n" +
                        "        name: TestMod\n" +
                        "        type: mod\n" +
                        "        version:\n");

        assertEquals(0, rules.rules().size());
        assertEquals(1, rules.diagnostics.skipped);
        assertTrue(rules.diagnostics.summary().contains("missing version range"));
    }

    @Test
    public void emptyRulesetReportsDiagnostics() {
        CommunityRules rules = load(
                "ruleset:\n" +
                        "  id: test\n" +
                        "  version: 1\n" +
                        "  minEngine: 1\n" +
                        "rules: []\n");

        assertEquals(0, rules.rules().size());
        assertEquals(1, rules.diagnostics.skipped);
        assertTrue(rules.diagnostics.summary().contains("no rules"));
    }

    @Test
    public void oversizedRulesetsFailOpen() {
        StringBuilder large = new StringBuilder();
        large.append("ruleset:\n  id: test\n  version: 1\nrules:\n");
        for (int i = 0; i < 270000; i++) {
            large.append('x');
        }

        CommunityRules rules = load(large.toString());

        assertEquals(0, rules.rules().size());
        assertTrue(rules.diagnostics.summary().contains("file too large"));
    }

    private static CommunityRules load(String yaml) {
        return CommunityRules.load(new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)), "test.yml");
    }
}
