package es.cobayka.bulwark;

final class RulePackInfo {
    static final RulePackInfo EMPTY = new RulePackInfo("", "", 1, "");

    final String id;
    final String version;
    final int minEngine;
    final String source;

    RulePackInfo(String id, String version, int minEngine, String source) {
        this.id = clean(id);
        this.version = clean(version);
        this.minEngine = minEngine;
        this.source = clean(source);
    }

    private static String clean(String value) {
        return value == null ? "" : value.trim();
    }
}
