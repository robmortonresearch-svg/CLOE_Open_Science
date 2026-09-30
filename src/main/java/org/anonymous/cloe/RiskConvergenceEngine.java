package org.anonymous.cloe;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Risk Convergence Engine: Online selection algorithm that processes a queue
 * of active vulnerabilities and selects optimal defensive actions.
 * Implements constraint penalties for deployment window latency.
 */
public class RiskConvergenceEngine {
    private static final long DEPLOYMENT_WINDOW_DAYS = 30;
    private static final double LATENCY_PENALTY_MULTIPLIER = 2.5;

    private final PomisOptimizer pomisOptimizer;
    private final Instant evaluationTime;
    private final Queue<WorldModel> vulnerabilityQueue;
    private final Map<String, DefensiveAction> selectedActions;

    public RiskConvergenceEngine(Instant evaluationTime) {
        this.pomisOptimizer = new PomisOptimizer();
        this.evaluationTime = evaluationTime;
        this.vulnerabilityQueue = new PriorityQueue<>(
                Comparator.comparingDouble(WorldModel::getRiskScore).reversed()
        );
        this.selectedActions = new LinkedHashMap<>();
    }

    /**
     * Enqueues a vulnerability for processing.
     */
    public void enqueue(WorldModel vulnerability) {
        vulnerabilityQueue.offer(vulnerability);
    }

    /**
     * Processes the vulnerability queue and selects optimal actions.
     */
    public Map<String, DefensiveAction> processQueue() {
        while (!vulnerabilityQueue.isEmpty()) {
            WorldModel vuln = vulnerabilityQueue.poll();
            DefensiveAction selected = selectOptimalAction(vuln);
            selectedActions.put(vuln.getTaskId(), selected);
        }
        return selectedActions;
    }

    /**
     * Selects the optimal defensive action for a vulnerability.
     * Prioritizes based on marginal utility (Risk Reduction / Defender Cost).
     * Applies latency penalty if vulnerability is in deployment window.
     */
    private DefensiveAction selectOptimalAction(WorldModel vulnerability) {
        Set<DefensiveAction> allActions = new HashSet<>(Arrays.asList(DefensiveAction.values()));
        Set<DefensiveAction> optimized = pomisOptimizer.optimizeActions(vulnerability, allActions);

        if (optimized.isEmpty()) {
            return DefensiveAction.LOG;
        }

        DefensiveAction best = optimized.stream()
                .max(Comparator.comparingDouble(action ->
                        computeMarginalUtility(vulnerability, action)))
                .orElse(DefensiveAction.LOG);

        return best;
    }

    /**
     * Computes marginal utility: Risk Reduction / (Defender Cost * Latency Penalty)
     */
    private double computeMarginalUtility(
            WorldModel vulnerability,
            DefensiveAction action) {

        double riskReduction = computeRiskReduction(vulnerability, action);
        double adjustedCost = computeAdjustedCost(vulnerability, action);

        return (adjustedCost > 0) ? riskReduction / adjustedCost : 0.0;
    }

    /**
     * Computes risk reduction: how much the action mitigates the vulnerability's risk.
     */
    private double computeRiskReduction(
            WorldModel vulnerability,
            DefensiveAction action) {

        double baselineRisk = vulnerability.getRiskScore();

        double mitigationRate = switch (action) {
            case HOTFIX -> 1.0;
            case PATCH -> 0.95;
            case BLOCK -> 0.85;
            case REDIRECT -> 0.70;
            case ALLOW -> 0.30;
            case LOG -> 0.05;
        };

        return baselineRisk * mitigationRate;
    }

    /**
     * Computes adjusted cost with 30-Day Latency Penalty.
     * If the vulnerability is discovered within the deployment window,
     * HOTFIX cost is inflated by the latency penalty multiplier.
     */
    private double computeAdjustedCost(
            WorldModel vulnerability,
            DefensiveAction action) {

        double baseCost = action.getCost();

        if (action == DefensiveAction.HOTFIX && vulnerability.isInDeploymentWindow()) {
            long hoursSinceDiscovery = Duration.between(
                    vulnerability.getDiscoveryTime(),
                    evaluationTime
            ).toHours();

            if (hoursSinceDiscovery < DEPLOYMENT_WINDOW_DAYS * 24) {
                baseCost *= LATENCY_PENALTY_MULTIPLIER;
            }
        }

        return baseCost;
    }

    /**
     * Retrieves the selected action for a specific vulnerability.
     */
    public DefensiveAction getSelectedAction(String taskId) {
        return selectedActions.getOrDefault(taskId, DefensiveAction.LOG);
    }

    /**
     * Returns all selected actions.
     */
    public Map<String, DefensiveAction> getSelectedActions() {
        return new LinkedHashMap<>(selectedActions);
    }

    /**
     * Computes aggregate statistics.
     */
    public EngineStatistics computeStatistics() {
        int total = selectedActions.size();
        long blockingActions = selectedActions.values().stream()
                .filter(a -> a == DefensiveAction.BLOCK || a == DefensiveAction.REDIRECT)
                .count();

        double exploitBlockRate = (total > 0) ? (double) blockingActions / total : 0.0;

        return new EngineStatistics(total, exploitBlockRate);
    }

    public static class EngineStatistics {
        public final int totalProcessed;
        public final double exploitBlockRate;

        public EngineStatistics(int totalProcessed, double exploitBlockRate) {
            this.totalProcessed = totalProcessed;
            this.exploitBlockRate = exploitBlockRate;
        }
    }
}
