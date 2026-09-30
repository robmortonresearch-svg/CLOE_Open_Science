package org.anonymous.cloe;

import java.util.*;

/**
 * POMIS (Pareto-Optimal Mitigation Intervention Selection) Offline Learning Engine.
 * Implements causal efficacy filtering and economic dominance pruning.
 */
public class PomisOptimizer {
    private static final double EFFICACY_THRESHOLD = 0.5;

    /**
     * Filters actions that causally mitigate the threat.
     * Only actions whose mitigation strength exceeds the threshold are retained.
     */
    public Set<DefensiveAction> causalEfficacyFilter(
            WorldModel vulnerability,
            Set<DefensiveAction> candidateActions) {

        Set<DefensiveAction> efficaciousActions = new HashSet<>();

        for (DefensiveAction action : candidateActions) {
            double mitigationStrength = computeMitigationStrength(vulnerability, action);
            if (mitigationStrength >= EFFICACY_THRESHOLD) {
                efficaciousActions.add(action);
            }
        }

        return efficaciousActions;
    }

    /**
     * Computes the causal mitigation strength of an action against a vulnerability.
     * Higher severity vulnerabilities require more direct mitigation (HOTFIX/PATCH).
     */
    private double computeMitigationStrength(
            WorldModel vulnerability,
            DefensiveAction action) {

        double baseStrength = switch (action) {
            case HOTFIX -> 1.0;     // Perfect mitigation
            case PATCH -> 0.95;     // Near-perfect after deployment
            case BLOCK -> 0.85;     // Network-level prevention
            case REDIRECT -> 0.70;  // Deflection-based (honeypot)
            case ALLOW -> 0.30;     // Monitoring only, low efficacy
            case LOG -> 0.05;       // Minimal efficacy
        };

        double severityModifier = vulnerability.getSeverity().getBaseRisk();
        return baseStrength * (1.0 - (severityModifier * 0.2));
    }

    /**
     * Economic dominance pruning: removes actions that are dominated by
     * cheaper, causally-equivalent alternatives.
     */
    public Set<DefensiveAction> economicDominancePruning(
            Set<DefensiveAction> efficaciousActions,
            WorldModel vulnerability) {

        Set<DefensiveAction> prunedActions = new HashSet<>(efficaciousActions);

        double blockEfficacy = getMitigationStrength(vulnerability, DefensiveAction.BLOCK);
        double redirectEfficacy = getMitigationStrength(vulnerability, DefensiveAction.REDIRECT);
        double hotfixEfficacy = getMitigationStrength(vulnerability, DefensiveAction.HOTFIX);
        double patchEfficacy = getMitigationStrength(vulnerability, DefensiveAction.PATCH);

        // HOTFIX is dominated if BLOCK or REDIRECT achieves similar efficacy at 1-2 orders of magnitude lower cost
        if (prunedActions.contains(DefensiveAction.HOTFIX)) {
            if (prunedActions.contains(DefensiveAction.BLOCK) &&
                    blockEfficacy >= (hotfixEfficacy * 0.90)) {
                prunedActions.remove(DefensiveAction.HOTFIX);
            } else if (prunedActions.contains(DefensiveAction.REDIRECT) &&
                    redirectEfficacy >= (hotfixEfficacy * 0.85)) {
                prunedActions.remove(DefensiveAction.HOTFIX);
            }
        }

        // PATCH is dominated if BLOCK achieves similar efficacy at lower cost
        if (prunedActions.contains(DefensiveAction.PATCH)) {
            if (prunedActions.contains(DefensiveAction.BLOCK) &&
                    blockEfficacy >= (patchEfficacy * 0.95)) {
                prunedActions.remove(DefensiveAction.PATCH);
            }
        }

        return prunedActions;
    }

    private double getMitigationStrength(WorldModel vulnerability, DefensiveAction action) {
        double baseStrength = switch (action) {
            case HOTFIX -> 1.0;
            case PATCH -> 0.95;
            case BLOCK -> 0.85;
            case REDIRECT -> 0.70;
            case ALLOW -> 0.30;
            case LOG -> 0.05;
        };
        double severityModifier = vulnerability.getSeverity().getBaseRisk();
        return baseStrength * (1.0 - (severityModifier * 0.2));
    }

    /**
     * Runs the complete POMIS offline optimization pipeline.
     */
    public Set<DefensiveAction> optimizeActions(
            WorldModel vulnerability,
            Set<DefensiveAction> candidateActions) {

        Set<DefensiveAction> efficacious = causalEfficacyFilter(vulnerability, candidateActions);
        if (efficacious.isEmpty()) {
            return Set.of(DefensiveAction.LOG);
        }

        return economicDominancePruning(efficacious, vulnerability);
    }
}
