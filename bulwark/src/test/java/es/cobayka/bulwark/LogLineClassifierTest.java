package es.cobayka.bulwark;

import org.junit.Test;

import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class LogLineClassifierTest {

    @Test
    public void detectsHighConfidenceSecurityAndWatchdogSignals() {
        Optional<Finding> jndi = LogLineClassifier.classify("[Server thread/INFO]: ${jndi:ldap://example/a}");
        assertTrue(jndi.isPresent());
        assertEquals("log-jndi-probe", jndi.get().id);
        assertEquals(Severity.HIGH, jndi.get().severity);

        Optional<Finding> watchdog = LogLineClassifier.classify("[Server Watchdog/FATAL]: A single server tick took 60.00 seconds");
        assertTrue(watchdog.isPresent());
        assertEquals("log-watchdog-freeze", watchdog.get().id);
    }

    @Test
    public void avoidsLooseWarnAndPlaceholderMatches() {
        assertFalse(LogLineClassifier.classify("[Server thread/WARN]: player wrote ${hello}").isPresent());
        assertFalse(LogLineClassifier.classify("[Server thread/WARN]: harmless warning").isPresent());
        assertFalse(LogLineClassifier.classify("This line says Exception without a class header").isPresent());
    }

    @Test
    public void detectsExceptionHeaderButNotStackFrames() {
        assertTrue(LogLineClassifier.classify("java.lang.NullPointerException: boom").isPresent());
        assertFalse(LogLineClassifier.classify("\tat com.example.Plugin.run(Plugin.java:42)").isPresent());
    }

    @Test
    public void longDenseDottedLineDoesNotCrashClassifier() {
        StringBuilder line = new StringBuilder(8192);
        for (int i = 0; i < 1600; i++) {
            line.append("word.");
        }
        assertFalse(LogLineClassifier.classify(line.toString()).isPresent());
    }
}
