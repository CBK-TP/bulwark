package es.cobayka.bulwark;

import org.bukkit.ChatColor;

/** How serious a finding is. The penalty feeds the overall score. */
enum Severity {
    CRITICAL(25, ChatColor.DARK_RED, "CRITICAL"),
    HIGH(12, ChatColor.RED, "HIGH"),
    MEDIUM(6, ChatColor.GOLD, "MEDIUM"),
    LOW(2, ChatColor.YELLOW, "LOW"),
    INFO(0, ChatColor.AQUA, "INFO");

    final int penalty;
    final ChatColor color;
    final String label;

    Severity(int penalty, ChatColor color, String label) {
        this.penalty = penalty;
        this.color = color;
        this.label = label;
    }
}
