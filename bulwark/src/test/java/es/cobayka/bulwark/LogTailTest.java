package es.cobayka.bulwark;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class LogTailTest {

    @Rule
    public TemporaryFolder temp = new TemporaryFolder();

    @Test
    public void decodeDropsFirstPartialLineAfterSeek() {
        List<String> lines = LogTail.decode("partial\ncomplete one\ncomplete two\n".getBytes(StandardCharsets.UTF_8), true, 10);
        assertEquals(Arrays.asList("complete one", "complete two"), lines);
    }

    @Test
    public void tailKeepsOnlyLatestLines() {
        List<String> lines = LogTail.tail(Arrays.asList("a", "b", "c", "d"), 2);
        assertEquals(Arrays.asList("c", "d"), lines);
    }

    @Test
    public void readLatestFileIsBoundedAndDropsPartialFirstLine() throws Exception {
        File latest = temp.newFile("latest.log");
        try (FileOutputStream out = new FileOutputStream(latest)) {
            out.write("partial-start-without-newline".getBytes(StandardCharsets.UTF_8));
            for (int i = 0; i < 180000; i++) {
                out.write(("\ncomplete-line-" + i).getBytes(StandardCharsets.UTF_8));
            }
        }

        LogTail.Read read = LogTail.readLatestFile(latest, 4096, 100);

        assertTrue(latest.length() > 2L * 1024L * 1024L);
        assertTrue(read.bytes <= 4096L);
        assertTrue(read.truncated);
        assertFalse(read.lines.isEmpty());
        assertTrue(read.lines.get(0).startsWith("complete-line-"));
        assertTrue(read.lines.size() <= 100);
    }

    @Test
    public void readGzipFileStopsAtByteCap() throws Exception {
        File gz = temp.newFile("2026-07-22-1.log.gz");
        try (GZIPOutputStream out = new GZIPOutputStream(new FileOutputStream(gz))) {
            for (int i = 0; i < 50000; i++) {
                out.write(("repeated server log line " + i + " repeated repeated repeated\n").getBytes(StandardCharsets.UTF_8));
            }
        }

        LogTail.Read read = LogTail.readGzipFile(gz, 2048, 500, System.currentTimeMillis() + 2000L);

        assertTrue(read.bytes <= 2048L);
        assertTrue(read.truncated);
        assertTrue(read.lines.size() <= 500);
    }
}
