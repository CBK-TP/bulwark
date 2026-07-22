package es.cobayka.bulwark;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class CommandSurfaceEntryTest {

    @Test
    public void detectsOperatorAndNamespaceRisks() {
        CommandSurface.Entry op = new CommandSurface.Entry("op", "Essentials", "", 1);
        assertTrue(op.risky());
        assertTrue(op.publicish());

        CommandSurface.Entry namespaced = new CommandSurface.Entry("minecraft:op", "minecraft", "", 2);
        assertTrue(namespaced.flags().contains("namespace"));
        assertTrue(namespaced.flags().contains("public-default"));
    }

    @Test
    public void classifiesLifecyclePluginManagerAndDisclosureCommands() {
        CommandSurface.Entry stop = new CommandSurface.Entry("stop", "minecraft", "", 3);
        assertTrue(stop.flags().contains("lifecycle"));

        CommandSurface.Entry plugman = new CommandSurface.Entry("plugman", "PlugManX", "", 4);
        assertTrue(plugman.flags().contains("plugin-manager"));

        CommandSurface.Entry plugins = new CommandSurface.Entry("plugins", "Bukkit", "", 5);
        assertTrue(plugins.flags().contains("disclosure"));
    }

    @Test
    public void leavesOrdinaryCommandsAsPlainSurface() {
        CommandSurface.Entry home = new CommandSurface.Entry("home", "Essentials", "", 6);
        assertFalse(home.risky());
        assertEquals("surface", home.flags());
    }
}
