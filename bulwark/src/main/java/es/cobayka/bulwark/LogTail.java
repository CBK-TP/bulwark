package es.cobayka.bulwark;

import org.bukkit.plugin.java.JavaPlugin;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FilenameFilter;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.zip.GZIPInputStream;

final class LogTail {

    private static final int DEFAULT_MAX_BYTES = 262144;
    private static final int DEFAULT_MAX_LINES = 500;
    private static final int DEFAULT_MAX_GZIP_BYTES = 8388608;
    private static final long DEFAULT_GZIP_DEADLINE_MS = 2000L;

    private final JavaPlugin plugin;
    private final ServerEnv env;

    LogTail(JavaPlugin plugin, ServerEnv env) {
        this.plugin = plugin;
        this.env = env;
    }

    LogScanResult scan() {
        try {
            int maxBytes = boundedInt("log-audit.max-bytes", DEFAULT_MAX_BYTES, 65536, 2097152);
            int maxLines = boundedInt("log-audit.max-lines", DEFAULT_MAX_LINES, 50, 5000);
            int maxGzipBytes = boundedInt("log-audit.max-gzip-bytes", DEFAULT_MAX_GZIP_BYTES, 1048576, 268435456);
            long gzipDeadline = Math.max(250L, plugin.getConfig().getLong("log-audit.gzip-deadline-ms", DEFAULT_GZIP_DEADLINE_MS));
            boolean includeRotated = plugin.getConfig().getBoolean("log-audit.include-rotated", true);

            List<String> lines = new ArrayList<>();
            boolean missingLatest = false;
            boolean truncated = false;
            long bytesRead = 0L;
            int sources = 0;
            String failure = "";

            if (includeRotated) {
                Read gz = readRecentGzip(maxGzipBytes, maxLines, gzipDeadline);
                if (!gz.lines.isEmpty()) {
                    lines.addAll(gz.lines);
                    sources++;
                    bytesRead += gz.bytes;
                    truncated |= gz.truncated;
                }
            }

            Read latest = readLatest(maxBytes, maxLines);
            missingLatest = latest.missing;
            if (!latest.failure.isEmpty()) {
                failure = latest.failure;
            }
            if (!latest.lines.isEmpty()) {
                lines.addAll(latest.lines);
                sources++;
                bytesRead += latest.bytes;
                truncated |= latest.truncated;
            }

            return new LogScanResult(tail(lines, maxLines), missingLatest, failure, sources, truncated, bytesRead);
        } catch (Throwable t) {
            return new LogScanResult(Collections.<String>emptyList(), true, safeMessage(t), 0, false, 0L);
        }
    }

    private Read readLatest(int maxBytes, int maxLines) {
        return readLatestFile(env.file("logs/latest.log"), maxBytes, maxLines);
    }

    static Read readLatestFile(File latest, int maxBytes, int maxLines) {
        if (latest == null || !latest.isFile() || !latest.canRead()) {
            return Read.missing("logs/latest.log");
        }
        try (RandomAccessFile raf = new RandomAccessFile(latest, "r")) {
            long len = raf.length();
            int n = (int) Math.min((long) maxBytes, len);
            long start = Math.max(0L, len - n);
            byte[] buf = new byte[n];
            raf.seek(start);
            raf.readFully(buf);
            return new Read(decode(buf, start > 0L, maxLines), false, "", n, start > 0L);
        } catch (Throwable t) {
            return Read.missing(safeMessage(t));
        }
    }

    private Read readRecentGzip(int maxBytes, int maxLines, long deadlineMs) {
        File logs = env.file("logs");
        File gz = newestGzip(logs);
        if (gz == null) {
            return Read.empty();
        }
        return readGzipFile(gz, maxBytes, maxLines, System.currentTimeMillis() + deadlineMs);
    }

    static Read readGzipFile(File gz, int maxBytes, int maxLines, long deadline) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(maxBytes, 65536));
        boolean truncated = false;
        byte[] buf = new byte[8192];
        try (GZIPInputStream in = new GZIPInputStream(new java.io.FileInputStream(gz))) {
            int n;
            while ((n = in.read(buf)) != -1) {
                if (System.currentTimeMillis() > deadline) {
                    truncated = true;
                    break;
                }
                int remaining = maxBytes - out.size();
                if (remaining <= 0) {
                    truncated = true;
                    break;
                }
                out.write(buf, 0, Math.min(n, remaining));
                if (n > remaining) {
                    truncated = true;
                    break;
                }
            }
            byte[] bytes = out.toByteArray();
            return new Read(decode(bytes, false, maxLines), false, "", bytes.length, truncated);
        } catch (Throwable ignored) {
            return Read.empty();
        }
    }

    private File newestGzip(File logs) {
        if (logs == null || !logs.isDirectory()) {
            return null;
        }
        File[] files = logs.listFiles(new FilenameFilter() {
            public boolean accept(File dir, String name) {
                return name.endsWith(".log.gz");
            }
        });
        if (files == null || files.length == 0) {
            return null;
        }
        File newest = null;
        for (File f : files) {
            if (newest == null || f.lastModified() > newest.lastModified()) {
                newest = f;
            }
        }
        return newest;
    }

    private int boundedInt(String path, int def, int min, int max) {
        int v = plugin.getConfig().getInt(path, def);
        if (v < min) {
            return min;
        }
        return Math.min(v, max);
    }

    static List<String> decode(byte[] bytes, boolean discardFirstPartial, int maxLines) {
        if (bytes == null || bytes.length == 0) {
            return Collections.emptyList();
        }
        int offset = 0;
        if (discardFirstPartial) {
            while (offset < bytes.length && bytes[offset] != '\n') {
                offset++;
            }
            if (offset >= bytes.length) {
                return Collections.emptyList();
            }
            offset++;
        }
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPLACE)
                    .onUnmappableCharacter(CodingErrorAction.REPLACE)
                    .decode(ByteBuffer.wrap(bytes, offset, bytes.length - offset)).toString();
        } catch (Throwable t) {
            text = new String(bytes, offset, bytes.length - offset, StandardCharsets.UTF_8);
        }
        String[] raw = text.split("\\r?\\n");
        List<String> lines = new ArrayList<>();
        for (String line : raw) {
            if (!line.isEmpty()) {
                lines.add(line);
            }
        }
        return tail(lines, maxLines);
    }

    static List<String> tail(List<String> lines, int maxLines) {
        if (lines.size() <= maxLines) {
            return Collections.unmodifiableList(new ArrayList<String>(lines));
        }
        return Collections.unmodifiableList(new ArrayList<String>(lines.subList(lines.size() - maxLines, lines.size())));
    }

    private static String safeMessage(Throwable t) {
        String m = t == null ? "" : t.getMessage();
        return m == null || m.trim().isEmpty() ? (t == null ? "" : t.getClass().getSimpleName()) : m.trim();
    }

    static final class LogScanResult {
        final List<String> lines;
        final boolean missingLatest;
        final String failure;
        final int sources;
        final boolean truncated;
        final long bytesRead;

        LogScanResult(List<String> lines, boolean missingLatest, String failure, int sources, boolean truncated, long bytesRead) {
            this.lines = lines;
            this.missingLatest = missingLatest;
            this.failure = failure == null ? "" : failure;
            this.sources = sources;
            this.truncated = truncated;
            this.bytesRead = bytesRead;
        }
    }

    static final class Read {
        final List<String> lines;
        final boolean missing;
        final String failure;
        final long bytes;
        final boolean truncated;

        Read(List<String> lines, boolean missing, String failure, long bytes, boolean truncated) {
            this.lines = lines;
            this.missing = missing;
            this.failure = failure == null ? "" : failure;
            this.bytes = bytes;
            this.truncated = truncated;
        }

        static Read empty() {
            return new Read(Collections.<String>emptyList(), false, "", 0L, false);
        }

        static Read missing(String failure) {
            return new Read(Collections.<String>emptyList(), true, failure, 0L, false);
        }
    }
}
