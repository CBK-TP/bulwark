package es.cobayka.bulwark;

final class RuleMatch {
    final Rule rule;
    final String evidence;
    final Severity severity;
    final boolean verifyManually;

    RuleMatch(Rule rule, String evidence) {
        this(rule, evidence, rule.severity, false);
    }

    RuleMatch(Rule rule, String evidence, Severity severity, boolean verifyManually) {
        this.rule = rule;
        this.evidence = evidence == null ? "" : evidence.trim();
        this.severity = severity == null ? rule.severity : severity;
        this.verifyManually = verifyManually;
    }

    Finding finding() {
        String source = rule.sources.isEmpty() ? "" : " Source: " + rule.sources.get(0);
        String detail = rule.detail;
        if (verifyManually) {
            detail += " Possibly affected - verify manually.";
        }
        if (!evidence.isEmpty()) {
            detail += " Evidence: " + evidence + ".";
        }
        detail += source;
        return new Finding(rule.id, CommunityRules.CATEGORY, severity,
                rule.title, detail, rule.fix, Baseline.COMMUNITY);
    }
}
