package es.cobayka.bulwark;

import org.junit.Test;

import java.util.Properties;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AuditEngineHelpersTest {

    @Test
    public void equalsTrimsAndKeepsMissingKeysSafe() {
        Properties p = new Properties();
        p.setProperty("online-mode", " FALSE ");

        assertTrue(AuditEngine.equals(p, "online-mode", "false"));
        assertFalse(AuditEngine.equals(p, "online-mode", "true"));
        assertFalse(AuditEngine.equals(p, "missing", "false"));
    }

    @Test
    public void valueAndIntValueUseSafeDefaults() {
        Properties p = new Properties();
        p.setProperty("max-players", " 42 ");
        p.setProperty("bad-number", "not-a-number");

        assertEquals("42", AuditEngine.value(p, "max-players"));
        assertEquals("", AuditEngine.value(p, "missing"));
        assertEquals(42, AuditEngine.intValue(p, "max-players", 20));
        assertEquals(20, AuditEngine.intValue(p, "bad-number", 20));
        assertEquals(20, AuditEngine.intValue(p, "missing", 20));
    }

    @Test
    public void connectionThrottleAdvisoryAvoidsProxyBackends() {
        assertTrue(AuditEngine.connectionThrottleNeedsAdvisory(0, false));
        assertTrue(AuditEngine.connectionThrottleNeedsAdvisory(-1, false));
        assertFalse(AuditEngine.connectionThrottleNeedsAdvisory(0, true));
        assertFalse(AuditEngine.connectionThrottleNeedsAdvisory(4000, false));
    }

    @Test
    public void logFindingsNeverAffectConfigGrade() {
        Finding f = new Finding("log-jndi-probe", "log", Severity.HIGH, "title", "detail", "fix");
        assertFalse(AuditEngine.graded(f));
    }

    @Test
    public void parseJavaMajorHandlesCommonVersionFormats() {
        assertEquals(8, AuditEngine.parseJavaMajor("1.8.0_302"));
        assertEquals(17, AuditEngine.parseJavaMajor("17.0.1"));
        assertEquals(21, AuditEngine.parseJavaMajor("21"));
        assertEquals(-1, AuditEngine.parseJavaMajor("garbage"));
    }

    @Test
    public void parseVersionAndIsBeforeCompareNumerically() {
        assertArrayEquals(new int[]{1, 20, 1}, AuditEngine.parseVersion("1.20.1"));
        assertTrue(AuditEngine.isBefore(new int[]{1, 17, 0}, new int[]{1, 18, 0}));
        assertFalse(AuditEngine.isBefore(new int[]{1, 20, 1}, new int[]{1, 20, 1}));
        assertFalse(AuditEngine.isBefore(new int[]{1, 20, 2}, new int[]{1, 20, 1}));
    }
}
