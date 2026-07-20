package es.cobayka.bulwark;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class CommandClassifierTest {

    @Test
    public void normalizeDropsNamespaceOnFirstToken() {
        assertEquals("op steve", CommandClassifier.normalize("/minecraft:op Steve"));
    }

    @Test
    public void exactLabelMatchDoesNotFlagPrivateMessage() {
        assertNull(CommandClassifier.match(CommandClassifier.normalize("/pm Steve hello"),
                Arrays.asList("op", "plugins", "permission set")));
    }

    @Test
    public void patternWithFirstArgumentIsExact() {
        assertEquals("whitelist off", CommandClassifier.match(CommandClassifier.normalize("/minecraft:whitelist off"),
                Arrays.asList("whitelist off")));
        assertNull(CommandClassifier.match(CommandClassifier.normalize("/whitelist add Steve"),
                Arrays.asList("whitelist off")));
    }
}
