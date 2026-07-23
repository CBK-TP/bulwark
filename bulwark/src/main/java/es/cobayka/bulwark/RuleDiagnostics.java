package es.cobayka.bulwark;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class RuleDiagnostics {
    int loaded;
    int skipped;
    private final List<String> issues = new ArrayList<>();

    void loaded() {
        loaded++;
    }

    void skip(String id, String reason) {
        skipped++;
        if (issues.size() < 12) {
            String cleanId = id == null || id.trim().isEmpty() ? "unknown" : id.trim();
            String cleanReason = reason == null || reason.trim().isEmpty() ? "invalid rule" : reason.trim();
            issues.add(cleanId + ": " + cleanReason);
        }
    }

    boolean hasIssues() {
        return skipped > 0 || !issues.isEmpty();
    }

    List<String> issues() {
        return Collections.unmodifiableList(issues);
    }

    String summary() {
        if (issues.isEmpty()) {
            return skipped + " skipped";
        }
        return skipped + " skipped (" + String.join("; ", issues) + ")";
    }
}
