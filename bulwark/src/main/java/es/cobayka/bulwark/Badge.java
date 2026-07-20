package es.cobayka.bulwark;

/**
 * Builds a shareable "security grade" badge - a shields.io-style SVG plus ready-to-paste Markdown
 * and BBCode. The admin shows it off in their server listing, Discord or forum signature, which
 * puts "audited with Bulwark" in front of other admins = organic word-of-mouth for the plugin.
 *
 * It's a LOCAL artifact (a file + text). Bulwark never hosts or serves it - no 24/7 infrastructure.
 */
final class Badge {

    private Badge() {
    }

    private static String color(char grade) {
        switch (grade) {
            case 'A': return "#3fb950"; // green
            case 'B': return "#56d364"; // green-ish
            case 'C': return "#d4a72c"; // yellow
            case 'D': return "#fb8500"; // orange
            default:  return "#e5534b"; // red (F)
        }
    }

    /** A self-contained shields-style SVG badge. No external fonts or resources. */
    static String svg(AuditEngine.Result r) {
        String label = "Bulwark security";
        String value = r.consented ? r.grade + "  " + r.score + "/100" : "not scanned";
        int labelW = 10 + label.length() * 6 + 8;
        int valueW = 10 + value.length() * 7 + 8;
        int total = labelW + valueW;
        String fill = r.consented ? color(r.grade) : "#8b949e";
        String font = "font-family='Verdana,DejaVu Sans,Geneva,sans-serif' font-size='11'";
        StringBuilder s = new StringBuilder();
        s.append("<svg xmlns='http://www.w3.org/2000/svg' width='").append(total).append("' height='20' role='img' aria-label='")
                .append(label).append(": ").append(value).append("'>");
        s.append("<linearGradient id='g' x2='0' y2='100%'><stop offset='0' stop-color='#bbb' stop-opacity='.1'/>")
                .append("<stop offset='1' stop-opacity='.1'/></linearGradient>");
        s.append("<clipPath id='r'><rect width='").append(total).append("' height='20' rx='3' fill='#fff'/></clipPath>");
        s.append("<g clip-path='url(#r)'>");
        s.append("<rect width='").append(labelW).append("' height='20' fill='#0f2233'/>");
        s.append("<rect x='").append(labelW).append("' width='").append(valueW).append("' height='20' fill='").append(fill).append("'/>");
        s.append("<rect width='").append(total).append("' height='20' fill='url(#g)'/></g>");
        s.append("<g fill='#fff' text-anchor='middle' ").append(font).append(">");
        s.append("<text x='").append(labelW / 2).append("' y='14'>").append(label).append("</text>");
        s.append("<text x='").append(labelW + valueW / 2).append("' y='14' font-weight='bold'>").append(value).append("</text>");
        s.append("</g></svg>");
        return s.toString();
    }

    /** A one-line Markdown snippet for a README / Discord / listing. */
    static String markdown(AuditEngine.Result r) {
        if (!r.consented) {
            return "_Bulwark: scan not authorized yet - run /bulwark consent._";
        }
        return "**Bulwark security: " + r.grade + " (" + r.score + "/100)** — audited with the free Bulwark plugin by Cobayka";
    }

    /** A BBCode snippet for a forum post or signature. */
    static String bbcode(AuditEngine.Result r) {
        if (!r.consented) {
            return "Bulwark: scan not authorized yet - run /bulwark consent.";
        }
        return "[B]Bulwark security: " + r.grade + " (" + r.score + "/100)[/B] - audited with the free Bulwark plugin by Cobayka";
    }
}
