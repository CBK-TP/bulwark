package es.cobayka.bulwark;

import org.junit.Test;

import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class CommunityRulesGradeIsolationTest {

    @Test
    public void communityFindingsDoNotEnterScoredFindingsOrBiggestWins() {
        Finding community = new Finding("community.test.high", CommunityRules.CATEGORY, Severity.HIGH,
                "Community advisory", "Detail", "Fix", Baseline.COMMUNITY);
        AuditEngine.Result result = new AuditEngine.Result(Collections.<Finding>emptyList(), 100, 'A',
                Collections.<AuditEngine.AreaGrade>emptyList(), "profile", "posture", true,
                Collections.singletonList(community));

        assertFalse(AuditEngine.graded(community));
        assertEquals(100, result.score);
        assertTrue(Report.biggestWins(result, 3).isEmpty());
        assertEquals(1, result.community.size());
    }
}
