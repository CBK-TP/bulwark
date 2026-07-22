package es.cobayka.bulwark;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class BaselineTest {

    @Test
    public void stableCodesCoverMainBaselineFamilies() {
        assertEquals("CHB-A1", Baseline.code("offline-mode"));
        assertEquals("CHB-R1", Baseline.code("rcon-no-password"));
        assertEquals("CHB-C1", Baseline.code("no-whitelist"));
        assertEquals("CHB-X2", Baseline.code("velocity-no-secret"));
        assertEquals("CHB-U2", Baseline.code("log4shell"));
        assertEquals("CHB-G1", Baseline.code("duplicate-plugins"));
        assertEquals("CHB-W2", Baseline.code("no-spawn-protection"));
        assertEquals("CHB-H3", Baseline.code("process-as-root"));
        assertEquals("CHB-D1", Baseline.code("no-rate-limit"));
        assertEquals("CHB-D9", Baseline.code("connection-throttle-off"));
        assertEquals("CHB-L1", Baseline.code("log-jndi-probe"));
    }

    @Test
    public void positiveAreaMappingsStayStable() {
        assertEquals("Authentication", Baseline.area("offline-mode"));
        assertEquals("Host", Baseline.area("process-as-root"));
        assertEquals(Baseline.HARDENING, Baseline.area("log-jndi-probe"));
        assertEquals("", Baseline.code("totally-unknown-id"));
    }

    @Test
    public void codeFamiliesMatchGradedAreasOrHardening() {
        List<String> sample = Arrays.asList(
                "offline-mode",
                "rcon-no-password",
                "no-whitelist",
                "velocity-no-secret",
                "old-java",
                "duplicate-plugins",
                "no-spawn-protection",
                "process-as-root",
                "no-rate-limit",
                "high-view-distance",
                "connection-throttle-off");

        for (String id : sample) {
            String code = Baseline.code(id);
            String area = Baseline.area(id);
            if (code.startsWith("CHB-D")) {
                assertEquals(Baseline.HARDENING, area);
            } else {
                assertTrue(Baseline.AREAS.contains(area));
                assertFalse(Baseline.HARDENING.equals(area));
            }
        }
    }
}
