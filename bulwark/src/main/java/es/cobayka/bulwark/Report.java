package es.cobayka.bulwark;

import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/** Turns an audit result into something readable - in chat, in the console, or a file. */
final class Report {

    private final BulwarkPlugin plugin;

    Report(BulwarkPlugin plugin) {
        this.plugin = plugin;
    }

    private String title() {
        return plugin.getConfig().getString("report-title", Messages.t("report.title", "Bulwark security audit"));
    }

    String summaryLine(AuditEngine.Result r) {
        if (!r.consented) {
            return Messages.t("report.not-authorized-line", "Scan not authorized yet - run /bulwark consent to enable it.");
        }
        return Messages.t("report.summary", "Security grade {0} ({1}/100) - {2}", r.grade, r.score, counts(r));
    }

    private String counts(AuditEngine.Result r) {
        int c = 0, h = 0, m = 0, lo = 0, inf = 0;
        for (Finding f : r.findings) {
            switch (f.severity) {
                case CRITICAL: c++; break;
                case HIGH: h++; break;
                case MEDIUM: m++; break;
                case LOW: lo++; break;
                default: inf++; break;
            }
        }
        return Messages.t("report.counts", "{0} critical, {1} high, {2} medium, {3} low, {4} info", c, h, m, lo, inf);
    }

    /** Prints the audit to a player or the console. {@code full} shows every finding. */
    void send(CommandSender to, AuditEngine.Result r, boolean full) {
        to.sendMessage(ChatColor.AQUA + "" + ChatColor.BOLD + title());
        if (!r.consented) {
            to.sendMessage(ChatColor.YELLOW + Messages.t("report.not-authorized", "Scan not authorized yet."));
            to.sendMessage(ChatColor.GRAY + Messages.t("report.consent-explain", "Bulwark hasn't read anything. It needs your one-time consent first - everything it reads is local and read-only."));
            to.sendMessage(ChatColor.GRAY + Messages.t("report.authorize-pre", "Authorize with ") + ChatColor.WHITE + "/bulwark consent"
                    + ChatColor.GRAY + Messages.t("report.authorize-post", " (revoke any time with /bulwark consent off)."));
            sendSupport(to);
            return;
        }
        ChatColor gc = gradeColor(r.grade);
        to.sendMessage(ChatColor.GRAY + Messages.t("report.grade-label", "Grade: ") + gc + ChatColor.BOLD + r.grade
                + ChatColor.GRAY + " (" + r.score + "/100) - " + counts(r));

        if (!r.areas.isEmpty()) {
            StringBuilder sb = new StringBuilder(ChatColor.GRAY + Messages.t("report.by-area", "By area: "));
            boolean first = true;
            for (AuditEngine.AreaGrade a : r.areas) {
                if (!first) {
                    sb.append(ChatColor.DARK_GRAY).append(" · ");
                }
                sb.append(ChatColor.GRAY).append(a.name).append(" ")
                        .append(gradeColor(a.grade)).append(a.grade);
                first = false;
            }
            to.sendMessage(sb.toString());
        }
        if (r.profile != null && !r.profile.isEmpty()) {
            to.sendMessage(ChatColor.DARK_GRAY + Messages.t("report.detected", "Detected: ") + r.profile);
        }

        if (r.findings.isEmpty()) {
            to.sendMessage(ChatColor.GREEN + Messages.t("report.no-issues", "No issues found. Nice and tidy."));
        } else {
            int shown = 0;
            for (Finding f : r.findings) {
                if (!full && f.severity == Severity.INFO) {
                    continue;
                }
                if (!full && shown >= 8) {
                    to.sendMessage(ChatColor.GRAY + Messages.t("report.and-more", "...and more. Use /bulwark full or /bulwark report."));
                    break;
                }
                String code = Baseline.code(f.id);
                String tag = code.isEmpty() ? "" : ChatColor.DARK_GRAY + " " + code;
                to.sendMessage(f.severity.color + "[" + f.severity.label + "] " + ChatColor.WHITE + f.title + tag);
                to.sendMessage(ChatColor.GRAY + "  " + f.detail);
                to.sendMessage(ChatColor.DARK_GRAY + "  " + Messages.t("report.fix-label", "Fix: ") + ChatColor.GRAY + f.fix);
                shown++;
            }
            for (String win : biggestWins(r, 3)) {
                to.sendMessage(ChatColor.GRAY + "  " + ChatColor.GREEN + "↑ " + ChatColor.GRAY + win);
            }
        }
        sendSupport(to);
    }

    /**
     * The "fix preview": fixing the highest-impact issues in order, what grade you'd reach. Pure
     * arithmetic on the penalties already computed - turns a list of problems into a path to A.
     */
    static java.util.List<String> biggestWins(AuditEngine.Result r, int max) {
        java.util.List<Finding> ranked = new java.util.ArrayList<>();
        int totalPenalty = 0;
        for (Finding f : r.findings) {
            if (AuditEngine.graded(f) && f.severity.penalty > 0) {
                ranked.add(f);
                totalPenalty += f.severity.penalty;
            }
        }
        ranked.sort((a, b) -> b.severity.penalty - a.severity.penalty); // biggest impact first
        java.util.List<String> out = new java.util.ArrayList<>();
        // Mirror the engine: score = max(0, 100 - remaining penalty). Subtract as we "fix" each one.
        int remaining = totalPenalty;
        int n = 0;
        for (Finding f : ranked) {
            if (n >= max) {
                break;
            }
            remaining -= f.severity.penalty;
            int proj = Math.max(0, 100 - remaining);
            out.add(Messages.t("report.win", "Fix {0}\"{1}\" -> grade {2} ({3})", (n == 0 ? "" : "+ "), f.title, gradeOf(proj), proj));
            n++;
        }
        return out;
    }

    private static char gradeOf(int score) {
        return score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
    }

    private static ChatColor gradeColor(char grade) {
        return grade <= 'B' ? ChatColor.GREEN : (grade == 'C' ? ChatColor.YELLOW : ChatColor.RED);
    }

    private void sendSupport(CommandSender to) {
        String support = plugin.getConfig().getString("support-message", "");
        if (support != null && !support.isEmpty()) {
            to.sendMessage(ChatColor.translateAlternateColorCodes('&', support));
        }
    }

    /** Writes the full audit to plugins/Bulwark/audit-<stamp>.txt. Returns the file, or null on failure. */
    File writeFile(AuditEngine.Result r, String stamp) {
        plugin.getDataFolder().mkdirs();
        File out = new File(plugin.getDataFolder(), "audit-" + stamp + ".txt");
        File tmp = tmp(out);
        PrintWriter w = null;
        try {
            w = writer(tmp);
            w.println(title());
            w.println(Messages.t("report.generated", "Generated: ") + stamp);
            w.println(Messages.t("report.grade-label", "Grade: ") + r.grade + " (" + r.score + "/100) - " + counts(r));
            if (!r.areas.isEmpty()) {
                StringBuilder sb = new StringBuilder(Messages.t("report.by-area", "By area: "));
                boolean first = true;
                for (AuditEngine.AreaGrade a : r.areas) {
                    if (!first) {
                        sb.append(" | ");
                    }
                    sb.append(a.name).append(" ").append(a.grade).append(" (").append(a.score).append(")");
                    first = false;
                }
                w.println(sb.toString());
            }
            w.println("------------------------------------------------------------");
            if (r.findings.isEmpty()) {
                w.println(Messages.t("report.no-issues", "No issues found. Nice and tidy."));
            } else {
                for (Finding f : r.findings) {
                    String code = Baseline.code(f.id);
                    w.println("[" + f.severity.label + "] " + (code.isEmpty() ? "" : code + " ") + f.title
                            + "   id: " + f.id);
                    w.println("  " + f.detail);
                    w.println("  Fix: " + f.fix);
                    w.println();
                }
            }
            String support = plugin.getConfig().getString("support-message", "");
            if (support != null && !support.isEmpty()) {
                w.println("------------------------------------------------------------");
                w.println(ChatColor.stripColor(ChatColor.translateAlternateColorCodes('&', support)));
            }
            if (bad(w)) {
                tmp.delete();
                return null;
            }
        } catch (Exception ex) {
            tmp.delete();
            return null;
        } finally {
            if (w != null) {
                w.close();
            }
        }
        return publish(tmp, out);
    }

    /** Writes the shareable security badge (plugins/Bulwark/badge.svg). Returns the file, or null. */
    File writeBadge(AuditEngine.Result r) {
        plugin.getDataFolder().mkdirs();
        File out = new File(plugin.getDataFolder(), "badge.svg");
        File tmp = tmp(out);
        PrintWriter w = null;
        try {
            w = writer(tmp);
            w.print(Badge.svg(r));
            if (bad(w)) {
                tmp.delete();
                return null;
            }
        } catch (Exception ex) {
            tmp.delete();
            return null;
        } finally {
            if (w != null) {
                w.close();
            }
        }
        return publish(tmp, out);
    }

    /**
     * Writes a shareable Markdown report (plugins/Bulwark/audit-<stamp>.md) - the kind of thing an
     * admin pastes into a ticket or Discord. Maps every finding to its Cobayka Hardening Baseline ID.
     */
    File writeMarkdown(AuditEngine.Result r, String stamp) {
        plugin.getDataFolder().mkdirs();
        File out = new File(plugin.getDataFolder(), "audit-" + stamp + ".md");
        File tmp = tmp(out);
        PrintWriter w = null;
        try {
            w = writer(tmp);
            w.println("# " + strip(title()));
            w.println();
            w.println(Messages.t("report.md-grade", "**Grade: {0} ({1}/100)** — {2}  ", r.grade, r.score, counts(r)));
            w.println(Messages.t("report.md-generated", "_Generated {0} · mapped to the Cobayka Hardening Baseline_", stamp));
            w.println();
            if (r.profile != null && !r.profile.isEmpty()) {
                w.println(Messages.t("report.md-detected", "**Detected:** ") + strip(r.profile));
                w.println();
            }

            if (!r.areas.isEmpty()) {
                w.println(Messages.t("report.md-subgrades", "## Sub-grades by area"));
                w.println();
                w.println(Messages.t("report.md-thead", "| Area | Grade | Score |"));
                w.println("|---|:---:|---:|");
                for (AuditEngine.AreaGrade a : r.areas) {
                    w.println("| " + a.name + " | **" + a.grade + "** | " + a.score + "/100 |");
                }
                w.println();
            }

            java.util.List<String> wins = biggestWins(r, 3);
            if (!wins.isEmpty()) {
                w.println(Messages.t("report.md-wins", "## Biggest wins"));
                w.println();
                for (String win : wins) {
                    w.println("- " + win);
                }
                w.println();
            }

            w.println(Messages.t("report.md-findings", "## Findings"));
            w.println();
            if (r.findings.isEmpty()) {
                w.println(Messages.t("report.no-issues", "No issues found. Nice and tidy."));
            } else {
                // Security findings first, then advisory.
                writeFindingBlock(w, r, false);
                writeFindingBlock(w, r, true);
            }

            String support = plugin.getConfig().getString("support-message", "");
            if (support != null && !support.isEmpty()) {
                w.println("---");
                w.println();
                w.println("_" + strip(support) + "_");
            }
            if (bad(w)) {
                tmp.delete();
                return null;
            }
        } catch (Exception ex) {
            tmp.delete();
            return null;
        } finally {
            if (w != null) {
                w.close();
            }
        }
        return publish(tmp, out);
    }

    private static PrintWriter writer(File file) throws Exception {
        return new PrintWriter(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8));
    }

    private static boolean bad(PrintWriter w) {
        w.flush();
        boolean failed = w.checkError();
        w.close();
        return failed || w.checkError();
    }

    private static File tmp(File out) {
        return new File(out.getParentFile(), out.getName() + ".tmp");
    }

    private static File publish(File tmp, File out) {
        try {
            Files.move(tmp.toPath(), out.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            return out;
        } catch (Exception noAtomic) {
            try {
                Files.move(tmp.toPath(), out.toPath(), StandardCopyOption.REPLACE_EXISTING);
                return out;
            } catch (Exception ex) {
                tmp.delete();
                return null;
            }
        }
    }

    private void writeFindingBlock(PrintWriter w, AuditEngine.Result r, boolean advisoryOnly) {
        boolean wroteHeader = false;
        for (Finding f : r.findings) {
            boolean advisory = !AuditEngine.graded(f);
            if (advisory != advisoryOnly) {
                continue;
            }
            if (advisoryOnly && !wroteHeader) {
                w.println(Messages.t("report.md-advisory", "### Advisory (not graded)"));
                w.println();
                wroteHeader = true;
            }
            String code = Baseline.code(f.id);
            w.println("- **[" + f.severity.label + "]** " + strip(f.title)
                    + (code.isEmpty() ? "" : "  `" + code + "`"));
            w.println("  - " + strip(f.detail));
            w.println("  - " + Messages.t("report.md-fix", "**Fix:** ") + strip(f.fix));
        }
        if (!advisoryOnly) {
            w.println();
        }
    }

    private static String strip(String s) {
        return s == null ? "" : ChatColor.stripColor(ChatColor.translateAlternateColorCodes('&', s));
    }
}
