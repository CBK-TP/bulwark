package es.cobayka.bulwark;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class FindingAreaTest {

    @Test
    public void unknownFindingKeepsVisibleOtherArea() {
        Finding f = new Finding("community.unmapped", "plugins", Severity.MEDIUM, "title", "detail", "fix");
        assertEquals(Baseline.OTHER, f.area);
        assertTrue(AuditEngine.graded(f));
    }

    @Test
    public void hardeningFindingDoesNotAffectGrade() {
        Finding f = new Finding("no-rate-limit", "core", Severity.LOW, "title", "detail", "fix");
        assertEquals(Baseline.HARDENING, f.area);
        assertFalse(AuditEngine.graded(f));
    }
}
