package es.cobayka.bulwark;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class UpdateCheckerTest {

    @Test
    public void isNewerComparesDottedNumbersNumerically() {
        assertTrue(UpdateChecker.isNewer("1.2.0", "1.1.9"));
        assertTrue(UpdateChecker.isNewer("1.10", "1.9"));
        assertFalse(UpdateChecker.isNewer("1.2.0", "1.10.0"));
        assertFalse(UpdateChecker.isNewer("1.2.0", "1.2.0"));
        assertFalse(UpdateChecker.isNewer("1.2", "1.2.0"));
        assertFalse(UpdateChecker.isNewer("1.2.0", "1.2"));
        assertFalse(UpdateChecker.isNewer("1.2.0-SNAPSHOT", "1.2.0"));
        assertTrue(UpdateChecker.isNewer("v1.3", "1.2"));
        assertFalse(UpdateChecker.isNewer("garbage", "1.0"));
    }
}
