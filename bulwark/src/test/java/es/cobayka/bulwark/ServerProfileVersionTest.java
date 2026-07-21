package es.cobayka.bulwark;

import org.junit.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ServerProfileVersionTest {

    @Test
    public void parseMcHandlesSplitMinecraftVersions() throws Exception {
        assertArrayEquals(new int[]{1, 20, 1}, parseMc("1.20.1"));
        assertArrayEquals(new int[]{1, 21, 0}, parseMc("1.21"));
        assertArrayEquals(new int[]{0, 0, 0}, parseMc(""));
        assertArrayEquals(new int[]{0, 0, 0}, parseMc("garbage"));
    }

    @Test
    public void rawBukkitVersionKeepsCurrentParserBehavior() throws Exception {
        assertArrayEquals(new int[]{1, 20, 10}, parseMc("1.20.1-R0.1-SNAPSHOT"));
    }

    @Test
    public void atLeastFailsOpenWhenMinecraftVersionIsUnknown() throws Exception {
        assertTrue(profile(0, 0, 0).atLeast(1, 20, 5));
    }

    @Test
    public void atLeastComparesMajorMinorAndPatch() throws Exception {
        assertTrue(profile(1, 21, 0).atLeast(1, 20, 5));
        assertTrue(profile(1, 20, 5).atLeast(1, 20, 5));
        assertFalse(profile(1, 20, 4).atLeast(1, 20, 5));
        assertFalse(profile(1, 19, 4).atLeast(1, 20, 0));
    }

    private static int[] parseMc(String value) throws Exception {
        Method m = ServerProfile.class.getDeclaredMethod("parseMc", String.class);
        m.setAccessible(true);
        return (int[]) m.invoke(null, value);
    }

    private static ServerProfile profile(int major, int minor, int patch) throws Exception {
        Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
        Field theUnsafe = unsafeClass.getDeclaredField("theUnsafe");
        theUnsafe.setAccessible(true);
        Object unsafe = theUnsafe.get(null);
        Method allocateInstance = unsafeClass.getMethod("allocateInstance", Class.class);
        ServerProfile profile = (ServerProfile) allocateInstance.invoke(unsafe, ServerProfile.class);
        setInt(profile, "mcMajor", major);
        setInt(profile, "mcMinor", minor);
        setInt(profile, "mcPatch", patch);
        return profile;
    }

    private static void setInt(ServerProfile profile, String field, int value) throws Exception {
        Field f = ServerProfile.class.getDeclaredField(field);
        f.setAccessible(true);
        f.setInt(profile, value);
    }
}
