package es.cobayka.bulwark;

/** One thing the audit found, with a plain-English explanation and how to fix it. */
final class Finding {

    final String id;
    final String category;
    final Severity severity;
    final String title;
    final String detail;
    final String fix;
    final String area;

    Finding(String id, String category, Severity severity, String title, String detail, String fix) {
        this(id, category, severity, title, detail, fix, Baseline.area(id));
    }

    Finding(String id, String category, Severity severity, String title, String detail, String fix, String area) {
        this.id = id;
        this.category = category;
        this.severity = severity;
        this.title = title;
        this.detail = detail;
        this.fix = fix;
        this.area = area == null || area.trim().isEmpty() ? Baseline.OTHER : area;
    }
}
