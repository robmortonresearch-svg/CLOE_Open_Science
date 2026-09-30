package org.anonymous.cloe;

/**
 * Defines the action space for the CLOE architecture.
 * Each defensive action has an associated cost representing the economic burden
 * of implementation in a production environment.
 */
public enum DefensiveAction {
    HOTFIX(100_000, "Hotfix", "Immediate code deployment to production"),
    PATCH(10_000, "Patch", "Scheduled security patch"),
    BLOCK(1_000, "Block", "IP/request-level blocking"),
    REDIRECT(100, "Redirect", "Traffic redirection to honeypot"),
    ALLOW(10, "Allow", "Explicitly allow with monitoring"),
    LOG(1, "Log", "Log and observe");

    private final int cost;
    private final String displayName;
    private final String description;

    DefensiveAction(int cost, String displayName, String description) {
        this.cost = cost;
        this.displayName = displayName;
        this.description = description;
    }

    public int getCost() {
        return cost;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }

    public boolean isDominant() {
        return this == HOTFIX;
    }
}
