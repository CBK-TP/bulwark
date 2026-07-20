package es.cobayka.bulwark;

import java.util.Collection;
import java.util.Locale;

final class CommandClassifier {

    private CommandClassifier() {
    }

    static String normalize(String raw) {
        if (raw == null) {
            return "";
        }
        String c = raw.trim();
        while (c.startsWith("/")) {
            c = c.substring(1);
        }
        c = c.toLowerCase(Locale.ROOT).trim();
        if (c.isEmpty()) {
            return "";
        }
        int space = c.indexOf(' ');
        String first = space < 0 ? c : c.substring(0, space);
        String rest = space < 0 ? "" : c.substring(space);
        int colon = first.indexOf(':');
        if (colon >= 0) {
            first = first.substring(colon + 1);
        }
        return (first + rest).trim();
    }

    static String label(String normalized) {
        int sp = normalized.indexOf(' ');
        return sp < 0 ? normalized : normalized.substring(0, sp);
    }

    static String firstArg(String normalized) {
        int sp = normalized.indexOf(' ');
        if (sp < 0) {
            return "";
        }
        String rest = normalized.substring(sp + 1).trim();
        int sp2 = rest.indexOf(' ');
        return sp2 < 0 ? rest : rest.substring(0, sp2);
    }

    static String match(String normalized, Collection<String> patterns) {
        if (normalized.isEmpty()) {
            return null;
        }
        String label = label(normalized);
        String firstArg = firstArg(normalized);
        for (String p : patterns) {
            if (p == null) {
                continue;
            }
            String pat = p.trim().toLowerCase(Locale.ROOT);
            if (pat.isEmpty()) {
                continue;
            }
            int sp = pat.indexOf(' ');
            if (sp < 0) {
                if (label.equals(pat)) {
                    return pat;
                }
            } else {
                String pl = pat.substring(0, sp);
                String pa = pat.substring(sp + 1).trim();
                if (label.equals(pl) && firstArg.equals(pa)) {
                    return pat;
                }
            }
        }
        return null;
    }
}
