package es.cobayka.bulwark;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class VersionRangeTest {

    @Test
    public void simpleRangesCompareNumerically() {
        VersionRange range = VersionRange.parse("< 1.106.0");

        assertTrue(range.valid());
        assertEquals(VersionRange.MATCH, range.test("1.105.9"));
        assertEquals(VersionRange.NO_MATCH, range.test("1.106.0"));
        assertEquals(VersionRange.NO_MATCH, range.test("1.120.0"));
    }

    @Test
    public void compoundRangesRequireEveryCheck() {
        VersionRange range = VersionRange.parse(">= 1.2.0 < 1.8.3");

        assertTrue(range.valid());
        assertEquals(VersionRange.MATCH, range.test("1.2.0"));
        assertEquals(VersionRange.MATCH, range.test("1.8.2"));
        assertEquals(VersionRange.NO_MATCH, range.test("1.8.3"));
        assertEquals(VersionRange.NO_MATCH, range.test("1.1.9"));
    }

    @Test
    public void minecraftBranchVersionsCompareByNumericSegments() {
        VersionRange range = VersionRange.parse("<= 1.20.1-1.0.11");

        assertEquals(VersionRange.MATCH, range.test("1.20.1-1.0.11"));
        assertEquals(VersionRange.MATCH, range.test("1.20.1-1.0.9"));
        assertEquals(VersionRange.NO_MATCH, range.test("1.20.1-1.0.13"));
    }

    @Test
    public void snapshotVersionsCompareAsTheirBaseBuild() {
        assertTrue(VersionRange.parseable("1.4.2-SNAPSHOT"));
        assertEquals(VersionRange.NO_MATCH, VersionRange.parse("< 1.4.2").test("1.4.2-SNAPSHOT"));
        assertEquals(VersionRange.MATCH, VersionRange.parse("<= 2.9.2").test("2.9.2-SNAPSHOT"));
    }

    @Test
    public void buildMetadataAndReleaseCandidatesCompareAsBaseBuild() {
        assertTrue(VersionRange.parseable("0.4.9+1.20.1"));
        assertEquals(VersionRange.MATCH, VersionRange.parse("<= 0.4.9").test("0.4.9+1.20.1"));
        assertEquals(VersionRange.NO_MATCH, VersionRange.parse("< 1.4.2").test("1.4.2-RC"));
    }

    @Test
    public void placeholdersStayUnknown() {
        assertFalse(VersionRange.parseable("${version}"));
        assertFalse(VersionRange.parseable("${file.jarVersion}"));
        assertEquals(VersionRange.UNKNOWN, VersionRange.parse("< 1.4.2").test("${file.jarVersion}"));
    }
}
