package es.cobayka.bulwark;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

final class VersionRange {
    static final int MATCH = 1;
    static final int NO_MATCH = 0;
    static final int UNKNOWN = -2;

    private final List<Check> checks;
    private final boolean valid;

    private VersionRange(List<Check> checks, boolean valid) {
        this.checks = checks;
        this.valid = valid;
    }

    static VersionRange parse(String expression) {
        if (expression == null || expression.trim().isEmpty()) {
            return new VersionRange(new ArrayList<Check>(), false);
        }
        List<Check> checks = new ArrayList<>();
        String[] parts = expression.replace(",", " ").trim().split("\\s+");
        for (int i = 0; i < parts.length; i++) {
            String op = parts[i].trim();
            if (op.isEmpty()) {
                continue;
            }
            String version;
            if (operator(op).isEmpty()) {
                op = "=";
                version = parts[i];
            } else if (op.length() > operator(op).length()) {
                String found = operator(op);
                version = op.substring(found.length());
                op = found;
            } else {
                if (i + 1 >= parts.length) {
                    return new VersionRange(checks, false);
                }
                version = parts[++i];
            }
            if (!parseable(version)) {
                return new VersionRange(checks, false);
            }
            checks.add(new Check(op, version));
        }
        return new VersionRange(checks, !checks.isEmpty());
    }

    boolean valid() {
        return valid;
    }

    int test(String version) {
        if (!valid || !parseable(version)) {
            return UNKNOWN;
        }
        for (Check check : checks) {
            int cmp = compare(version, check.version);
            if (cmp == UNKNOWN) {
                return UNKNOWN;
            }
            if (!check.accepts(cmp)) {
                return NO_MATCH;
            }
        }
        return MATCH;
    }

    static boolean parseable(String version) {
        return parts(version) != null;
    }

    static int compare(String left, String right) {
        List<Integer> a = parts(left);
        List<Integer> b = parts(right);
        if (a == null || b == null) {
            return UNKNOWN;
        }
        int n = Math.max(a.size(), b.size());
        for (int i = 0; i < n; i++) {
            int av = i < a.size() ? a.get(i) : 0;
            int bv = i < b.size() ? b.get(i) : 0;
            if (av < bv) {
                return -1;
            }
            if (av > bv) {
                return 1;
            }
        }
        return 0;
    }

    private static List<Integer> parts(String version) {
        if (version == null) {
            return null;
        }
        String v = version.trim().toLowerCase(Locale.ROOT);
        if (v.startsWith("v") && v.length() > 1 && Character.isDigit(v.charAt(1))) {
            v = v.substring(1);
        }
        int build = v.indexOf('+');
        if (build >= 0) {
            v = v.substring(0, build);
        }
        if (v.endsWith("-snapshot")) {
            v = v.substring(0, v.length() - "-snapshot".length());
        } else if (v.matches(".*-rc\\d*$")) {
            v = v.substring(0, v.lastIndexOf("-rc"));
        }
        if (v.isEmpty() || v.contains("${") || v.contains("*")) {
            return null;
        }
        String[] raw = v.split("[._\\-]");
        List<Integer> out = new ArrayList<>();
        for (String token : raw) {
            if (token.isEmpty()) {
                continue;
            }
            if (!numeric(token)) {
                return null;
            }
            try {
                out.add(Integer.valueOf(Integer.parseInt(token)));
            } catch (NumberFormatException ex) {
                return null;
            }
        }
        return out.isEmpty() ? null : out;
    }

    private static boolean numeric(String token) {
        for (int i = 0; i < token.length(); i++) {
            if (!Character.isDigit(token.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static String operator(String value) {
        for (String op : new String[]{"<=", ">=", "==", "!=", "<", ">", "="}) {
            if (value.startsWith(op)) {
                return op;
            }
        }
        return "";
    }

    private static final class Check {
        final String op;
        final String version;

        Check(String op, String version) {
            this.op = op;
            this.version = version;
        }

        boolean accepts(int cmp) {
            if ("<".equals(op)) {
                return cmp < 0;
            }
            if ("<=".equals(op)) {
                return cmp <= 0;
            }
            if (">".equals(op)) {
                return cmp > 0;
            }
            if (">=".equals(op)) {
                return cmp >= 0;
            }
            if ("!=".equals(op)) {
                return cmp != 0;
            }
            return cmp == 0;
        }
    }
}
