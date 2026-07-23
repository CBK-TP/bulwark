package es.cobayka.bulwark;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RedactorTest {

    @Test
    public void masksVanillaLoginAddressWithoutChangingVersions() {
        String out = Redactor.redact("Notch[/203.0.113.42:57950] logged in with entity id 12 at ([world]1.20.1)");
        assertTrue(out.contains("203.0.113.x:57950"));
        assertTrue(out.contains("1.20.1"));
        assertFalse(out.contains("203.0.113.42"));
    }

    @Test
    public void masksVanillaDisconnectAndCommandAddresses() {
        String disconnect = Redactor.redact("/127.0.0.1:57950 lost connection: Failed to verify username");
        assertTrue(disconnect.contains("127.0.0.x:57950"));
        assertFalse(disconnect.contains("127.0.0.1"));

        String command = Redactor.redact("[/198.51.100.7:25565] issued server command: /op Notch");
        assertTrue(command.contains("198.51.100.x:25565"));
        assertFalse(command.contains("198.51.100.7"));

        String loose = Redactor.redact("connection from 203.0.113.42");
        assertTrue(loose.contains("203.0.113.x"));
        assertFalse(loose.contains("203.0.113.42"));

        String player = Redactor.redact("player 203.0.113.42 joined");
        assertTrue(player.contains("203.0.113.x"));
        assertFalse(player.contains("203.0.113.42"));

        String banned = Redactor.redact("banned 203.0.113.42");
        assertTrue(banned.contains("203.0.113.x"));
        assertFalse(banned.contains("203.0.113.42"));

        String kicked = Redactor.redact("kicked Notch 203.0.113.42");
        assertTrue(kicked.contains("203.0.113.x"));
        assertFalse(kicked.contains("203.0.113.42"));

        String nameThenIp = Redactor.redact("Notch 203.0.113.42");
        assertTrue(nameThenIp.contains("203.0.113.x"));
        assertFalse(nameThenIp.contains("203.0.113.42"));

        String colon = Redactor.redact("address:203.0.113.42");
        assertTrue(colon.contains("address:203.0.113.x"));
        assertFalse(colon.contains("203.0.113.42"));
    }

    @Test
    public void masksVanillaIpv6MappedAndZoneAddresses() {
        String ipv6 = Redactor.redact("Steve[/[2001:db8::1]:54123] logged in with entity id 77");
        assertTrue(ipv6.contains("[ipv6]:54123"));
        assertFalse(ipv6.contains("2001:db8::1"));

        String mapped = Redactor.redact("/::ffff:203.0.113.42 lost connection: Disconnected");
        assertTrue(mapped.contains("::ffff:203.0.113.x"));
        assertFalse(mapped.contains("203.0.113.42"));

        String zone = Redactor.redact("/fe80::1%eth0 lost connection: Disconnected");
        assertTrue(zone.contains("[ipv6] lost connection"));
        assertFalse(zone.contains("fe80::1%eth0"));
    }

    @Test
    public void masksSecrets() {
        String out = Redactor.redact("token=abc123 password:open");
        assertTrue(out.contains("token=[redacted]"));
        assertTrue(out.contains("password=[redacted]"));
        assertFalse(out.contains("abc123"));
        assertFalse(out.contains("open"));
    }

    @Test
    public void masksWebhookUrls() {
        assertEquals("send [webhook-url]", Redactor.redact("send https://discord.com/api/webhooks/1/secret"));
    }

    @Test
    public void preservesVersionShapedTokensInArtifactAndLogContext() {
        String artifact = Redactor.redact("mods/OpenComputers.jar declares OpenComputers 1.7.5.192");
        assertTrue(artifact.contains("1.7.5.192"));
        assertFalse(artifact.contains("1.7.5.x"));

        String versionWord = Redactor.redact("OpenComputers version:1.7.5.192 failed during startup");
        assertTrue(versionWord.contains("1.7.5.192"));
        assertFalse(versionWord.contains("1.7.5.x"));

        String pathIp = Redactor.redact("mods/backup-to-203.0.113.45-cc.jar declares CC-Tweaked 1.20.1-1.105.0");
        assertTrue(pathIp.contains("203.0.113.x"));
        assertFalse(pathIp.contains("203.0.113.45"));
    }
}
