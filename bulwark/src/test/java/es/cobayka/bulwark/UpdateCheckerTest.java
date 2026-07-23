package es.cobayka.bulwark;

import org.junit.Test;

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

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

    @Test
    public void shouldNotifyAgainWhenLatestVersionChanges() {
        assertTrue(UpdateChecker.shouldNotify("1.2.0", null));
        assertFalse(UpdateChecker.shouldNotify("1.2.0", "1.2.0"));
        assertTrue(UpdateChecker.shouldNotify("1.2.1", "1.2.0"));
    }

    @Test
    public void updateModesPreserveLegacyCheckSetting() {
        assertEquals(UpdateChecker.Mode.NOTIFY, UpdateChecker.mode("", true, UpdateChecker.Mode.NOTIFY));
        assertEquals(UpdateChecker.Mode.OFF, UpdateChecker.mode("", false, UpdateChecker.Mode.NOTIFY));
        assertEquals(UpdateChecker.Mode.DOWNLOAD, UpdateChecker.mode("download", false, UpdateChecker.Mode.NOTIFY));
        assertEquals(UpdateChecker.Mode.NOTIFY, UpdateChecker.mode("garbage", null, UpdateChecker.Mode.NOTIFY));
        assertEquals(UpdateChecker.Mode.OFF, UpdateChecker.mode(Boolean.FALSE, null, UpdateChecker.Mode.NOTIFY));
        assertEquals(UpdateChecker.Mode.NOTIFY, UpdateChecker.mode(Boolean.TRUE, null, UpdateChecker.Mode.OFF));
    }

    @Test
    public void downloadModeRequiresFreeTierAndUpdateFolder() {
        assertEquals(UpdateChecker.Mode.DOWNLOAD,
                UpdateChecker.effectivePluginMode(UpdateChecker.Mode.DOWNLOAD, true, true));
        assertEquals(UpdateChecker.Mode.NOTIFY,
                UpdateChecker.effectivePluginMode(UpdateChecker.Mode.DOWNLOAD, false, true));
        assertEquals(UpdateChecker.Mode.NOTIFY,
                UpdateChecker.effectivePluginMode(UpdateChecker.Mode.DOWNLOAD, true, false));
        assertEquals(UpdateChecker.Mode.OFF,
                UpdateChecker.effectivePluginMode(UpdateChecker.Mode.OFF, true, true));
    }

    @Test
    public void manifestSignatureAndHashMustMatch() throws Exception {
        KeyPair pair = rsa();
        byte[] jar = "jar-bytes".getBytes(StandardCharsets.UTF_8);
        String hash = UpdateChecker.sha256(jar);
        String url = "https://updates.example.invalid/Bulwark-1.2.0.jar";
        String sig = sign(pair.getPrivate(), UpdateChecker.payload(UpdateChecker.KIND_PLUGIN, "1.2.0", url, hash));
        UpdateChecker.Manifest manifest = new UpdateChecker.Manifest("1.2.0",
                url, hash, sig);

        assertTrue(UpdateChecker.verifyManifest(pair.getPublic(), UpdateChecker.KIND_PLUGIN, manifest));
        assertTrue(UpdateChecker.hashMatches(jar, manifest.sha256));
        assertFalse(UpdateChecker.verifyManifest(pair.getPublic(), UpdateChecker.KIND_RULES, manifest));
        assertFalse(UpdateChecker.verifyManifest(pair.getPublic(), UpdateChecker.KIND_PLUGIN,
                new UpdateChecker.Manifest("1.2.1", manifest.url, hash, sig)));
        assertFalse(UpdateChecker.verifyManifest(pair.getPublic(), UpdateChecker.KIND_PLUGIN,
                new UpdateChecker.Manifest("1.2.0", "https://evil.example.invalid/Bulwark-1.2.0.jar", hash, sig)));
        assertFalse(UpdateChecker.verifyManifest(pair.getPublic(), UpdateChecker.KIND_PLUGIN,
                new UpdateChecker.Manifest("1.2.0", "http://updates.example.invalid/Bulwark-1.2.0.jar", hash, sig)));
        assertFalse(UpdateChecker.hashMatches("changed".getBytes(StandardCharsets.UTF_8), manifest.sha256));
        assertFalse(UpdateChecker.verifyManifest(pair.getPublic(), UpdateChecker.KIND_PLUGIN,
                new UpdateChecker.Manifest("1.2.0", manifest.url, hash, sig.substring(0, sig.length() - 2) + "AA")));
    }

    @Test
    public void preparedDownloadKeepsInstalledJarName() {
        File dest = UpdateChecker.destinationJar(new File("updates"),
                new File("plugins/Bulwark-1.0.0.jar"), "1.1.0");

        assertEquals("Bulwark-1.0.0.jar", dest.getName());
    }

    @Test
    public void redirectsToOtherHostOrProtocolAreRejected() throws Exception {
        URL from = new URL("https://updates.example.invalid/releases/manifest.json");

        assertTrue(UpdateChecker.sameHostRedirect(from, "/releases/Bulwark.jar"));
        assertTrue(UpdateChecker.sameHostRedirect(from, "https://updates.example.invalid/releases/Bulwark.jar"));
        assertFalse(UpdateChecker.sameHostRedirect(from, "https://evil.example.invalid/releases/Bulwark.jar"));
        assertFalse(UpdateChecker.sameHostRedirect(from, "http://updates.example.invalid/releases/Bulwark.jar"));
    }

    @Test
    public void remoteRulesMustValidateBeforeUse() {
        assertTrue(UpdateChecker.validRemoteRules((
                "ruleset:\n" +
                        "  id: test\n" +
                        "  version: 2026.07.23\n" +
                        "  minEngine: 1\n" +
                        "rules:\n" +
                        "  - id: community.test.valid-rules\n" +
                        "    severity: info\n" +
                        "    title: Test\n" +
                        "    detail: Detail\n" +
                        "    fix: Fix\n" +
                        "    when:\n" +
                        "      artifact:\n" +
                        "        name: TestMod\n" +
                        "        type: mod\n").getBytes(StandardCharsets.UTF_8)));
        assertFalse(UpdateChecker.validRemoteRules("ruleset:\n  id: test\nrules: []\n".getBytes(StandardCharsets.UTF_8)));
        assertFalse(UpdateChecker.validRemoteRules(new byte[0]));
    }

    @Test
    public void readLimitedHonorsOverallDeadline() throws Exception {
        InputStream drip = new InputStream() {
            @Override
            public int read(byte[] b, int off, int len) throws java.io.IOException {
                sleep();
                b[off] = 'x';
                return 1;
            }

            @Override
            public int read() throws java.io.IOException {
                sleep();
                return 'x';
            }

            private void sleep() throws java.io.IOException {
                try {
                    Thread.sleep(5);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    throw new java.io.InterruptedIOException();
                }
            }
        };

        try {
            UpdateChecker.readLimited(drip, 1024, System.currentTimeMillis() + 20);
            fail("expected read timeout");
        } catch (java.io.IOException ex) {
            assertTrue(ex.getMessage().contains("download timed out"));
        }
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private static String sign(PrivateKey key, byte[] payload) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key);
        signer.update(payload);
        return Base64.getEncoder().encodeToString(signer.sign());
    }
}
