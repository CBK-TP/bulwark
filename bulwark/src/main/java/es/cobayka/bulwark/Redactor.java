package es.cobayka.bulwark;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class Redactor {

    private static final Pattern SECRET = Pattern.compile("(?i)\\b((?:token|password|passwd|secret|authorization|rcon(?:\\.password)?))\\s*[:=]\\s*([^\\s,;&]+)");
    private static final Pattern WEBHOOK = Pattern.compile("(?i)https://(?:canary\\.)?discord(?:app)?\\.com/api/webhooks/[^\\s]+");
    private static final String IPV4_OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])";
    private static final String IPV4_ADDR = IPV4_OCTET + "\\." + IPV4_OCTET + "\\." + IPV4_OCTET + "\\." + IPV4_OCTET;
    private static final Pattern IPV4_MAPPED = Pattern.compile("(?i)(::ffff:)(" + IPV4_ADDR + ")(:\\d{1,5})?");
    private static final Pattern BRACKETED_IPV6 = Pattern.compile("\\[([0-9A-Za-z:.%_-]+:[0-9A-Za-z:.%_-]+)\\](?::(\\d{1,5}))?");
    private static final Pattern IPV4 = Pattern.compile("(?<![0-9A-Fa-f:.])(" + IPV4_ADDR + ")(:\\d{1,5})?(?![0-9A-Fa-f.])");

    private Redactor() {
    }

    static String redact(String line) {
        if (line == null || line.isEmpty()) {
            return "";
        }
        String s = WEBHOOK.matcher(line).replaceAll("[webhook-url]");
        s = SECRET.matcher(s).replaceAll("$1=[redacted]");
        return redactIpTokens(s);
    }

    private static String redactIpTokens(String line) {
        StringBuilder out = new StringBuilder(line.length());
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (Character.isWhitespace(c)) {
                flushToken(out, token);
                out.append(c);
            } else {
                token.append(c);
            }
        }
        flushToken(out, token);
        return out.toString();
    }

    private static void flushToken(StringBuilder out, StringBuilder token) {
        if (token.length() == 0) {
            return;
        }
        out.append(redactToken(token.toString()));
        token.setLength(0);
    }

    private static String redactToken(String token) {
        String masked = redactMappedIpv4(token);
        masked = redactBracketedIpv6(masked);
        masked = redactPlainIpv6(masked);
        return redactIpv4(masked);
    }

    private static String redactMappedIpv4(String token) {
        Matcher m = IPV4_MAPPED.matcher(token);
        StringBuffer out = new StringBuffer(token.length());
        while (m.find()) {
            String port = m.group(3) == null ? "" : m.group(3);
            m.appendReplacement(out, Matcher.quoteReplacement(m.group(1).toLowerCase(java.util.Locale.ROOT) + maskIpv4(m.group(2)) + port));
        }
        m.appendTail(out);
        return out.toString();
    }

    private static String redactBracketedIpv6(String token) {
        Matcher m = BRACKETED_IPV6.matcher(token);
        StringBuffer out = new StringBuffer(token.length());
        while (m.find()) {
            if (!validIpv6(m.group(1))) {
                continue;
            }
            String port = m.group(2) == null ? "" : ":" + m.group(2);
            m.appendReplacement(out, Matcher.quoteReplacement("[ipv6]" + port));
        }
        m.appendTail(out);
        return out.toString();
    }

    private static String redactPlainIpv6(String token) {
        StringBuilder out = new StringBuilder(token.length());
        int pos = 0;
        while (pos < token.length()) {
            int start = nextIpv6CandidateStart(token, pos);
            if (start < 0) {
                out.append(token.substring(pos));
                break;
            }
            out.append(token.substring(pos, start));
            int end = start + 1;
            while (end < token.length() && isIpv6CandidateChar(token.charAt(end))) {
                end++;
            }
            String candidate = token.substring(start, end);
            if (validIpv6(candidate)) {
                out.append("[ipv6]");
            } else {
                out.append(candidate);
            }
            pos = end;
        }
        return out.toString();
    }

    private static String redactIpv4(String token) {
        Matcher m = IPV4.matcher(token);
        StringBuffer out = new StringBuffer(token.length());
        while (m.find()) {
            String port = m.group(2) == null ? "" : m.group(2);
            m.appendReplacement(out, Matcher.quoteReplacement(maskIpv4(m.group(1)) + port));
        }
        m.appendTail(out);
        return out.toString();
    }

    private static String maskIpv4(String host) {
        String[] parts = host.split("\\.");
        if (parts.length != 4) {
            return host;
        }
        for (String p : parts) {
            if (!numeric(p)) {
                return host;
            }
            int n;
            try {
                n = Integer.parseInt(p);
            } catch (NumberFormatException ex) {
                return host;
            }
            if (n < 0 || n > 255) {
                return host;
            }
        }
        return parts[0] + "." + parts[1] + "." + parts[2] + ".x";
    }

    private static int nextIpv6CandidateStart(String token, int from) {
        for (int i = from; i < token.length(); i++) {
            char c = token.charAt(i);
            if (isHex(c) || c == ':') {
                return i;
            }
        }
        return -1;
    }

    private static boolean isIpv6CandidateChar(char c) {
        return Character.isLetterOrDigit(c) || c == ':' || c == '.' || c == '%' || c == '_' || c == '-';
    }

    private static boolean isHex(char c) {
        return c >= '0' && c <= '9'
                || c >= 'A' && c <= 'F'
                || c >= 'a' && c <= 'f';
    }

    private static boolean validIpv6(String value) {
        if (value == null || value.indexOf(':') < 0) {
            return false;
        }
        String base = stripZone(value);
        if (base.indexOf(':') < 0 || !base.matches("[0-9A-Fa-f:.]+")) {
            return false;
        }
        if (base.indexOf("::") < 0 && count(base, ':') < 7) {
            return false;
        }
        try {
            InetAddress a = InetAddress.getByName(base);
            return a instanceof Inet6Address;
        } catch (Exception ex) {
            return false;
        }
    }

    private static String stripZone(String value) {
        int percent = value.indexOf('%');
        return percent < 0 ? value : value.substring(0, percent);
    }

    private static int count(String s, char needle) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == needle) {
                n++;
            }
        }
        return n;
    }

    private static boolean numeric(String s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            if (!Character.isDigit(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }
}
