package es.cobayka.bulwark;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class Rule {
    final String id;
    final Severity severity;
    final String category;
    final String title;
    final String detail;
    final String fix;
    final List<String> sources;
    final Condition when;

    Rule(String id, Severity severity, String category, String title, String detail,
         String fix, List<String> sources, Condition when) {
        this.id = id;
        this.severity = severity;
        this.category = category;
        this.title = title;
        this.detail = detail;
        this.fix = fix;
        this.sources = Collections.unmodifiableList(new ArrayList<>(sources));
        this.when = when;
    }

    RuleMatch evaluate(CommunityRules.Context ctx) {
        return when.match(ctx, this);
    }

    interface Condition {
        RuleMatch match(CommunityRules.Context ctx, Rule rule);
    }
}
