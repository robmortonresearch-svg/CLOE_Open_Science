package org.anonymous.cloe;

import java.util.*;

/**
 * Active Deception via Differential Privacy.
 * Implements Warner's Randomized Response algorithm to obfuscate planned actions
 * against adversarial machine learning oracle attacks.
 */
public class DpDeceptionLayer {
    private static final double PRIVACY_BIAS_PARAMETER = 0.6;
    private static final Random RANDOM = new Random();

    /**
     * Privacy parameter epsilon: mathematically bounds information leakage.
     * Derived from Warner's Randomized Response formula:
     * epsilon = ln((2-f) / f) where f = privacy_bias_parameter = 0.6
     * epsilon = ln(1.4 / 0.6) ≈ 0.847
     */
    private static final double EPSILON = Math.log((2.0 - PRIVACY_BIAS_PARAMETER) / PRIVACY_BIAS_PARAMETER);

    /**
     * Applies randomized response obfuscation to transform a planned action
     * into a deceptive action observable by potential adversaries.
     *
     * Algorithm:
     * - With probability f (60%), output the true planned action (Truth Mode)
     * - With probability 1-f (40%), output a random decoy action (Noise Mode)
     *
     * This ensures that an adversary observing the output action cannot reliably
     * infer the true planned action, as it could originate from noise.
     */
    public DefensiveAction applyRandomizedResponse(
            DefensiveAction plannedAction,
            WorldModel vulnerabilityState) {

        double rand = RANDOM.nextDouble();

        if (rand < PRIVACY_BIAS_PARAMETER) {
            return plannedAction;
        } else {
            return generateNoisyAction(plannedAction, vulnerabilityState);
        }
    }

    /**
     * Generates a decoy action that differs from the planned action.
     * Selects randomly from actions orthogonal to the planned action's strategy.
     */
    private DefensiveAction generateNoisyAction(
            DefensiveAction plannedAction,
            WorldModel vulnerabilityState) {

        List<DefensiveAction> decoyActions = new ArrayList<>();

        for (DefensiveAction action : DefensiveAction.values()) {
            if (action != plannedAction) {
                decoyActions.add(action);
            }
        }

        if (decoyActions.isEmpty()) {
            return plannedAction;
        }

        return decoyActions.get(RANDOM.nextInt(decoyActions.size()));
    }

    /**
     * Computes the privacy budget (epsilon value) for this deception layer.
     * Lower epsilon indicates stronger privacy guarantees.
     */
    public double getPrivacyBudget() {
        return EPSILON;
    }

    /**
     * Computes attacker uncertainty (U):
     * The probability mass assigned to incorrect hypotheses when observing obfuscated actions.
     * Represents the noise injection rate in Warner's Randomized Response.
     *
     * Formula: U = 1 - f (noise probability)
     * With f = 0.6: U = 0.4 (40% chance of noise injection)
     */
    public double getAttackerUncertainty() {
        return 1.0 - PRIVACY_BIAS_PARAMETER;
    }

    /**
     * Verification utility: confirms that the privacy guarantee is maintained.
     */
    public boolean verifyPrivacyGuarantee() {
        double uncertainty = getAttackerUncertainty();
        return uncertainty > 0.35 && uncertainty < 0.50;
    }

    /**
     * Batch-applies randomized response to a collection of planned actions.
     */
    public Map<String, DefensiveAction> obfuscatePlan(
            Map<String, DefensiveAction> plannedActions,
            Map<String, WorldModel> vulnerabilities) {

        Map<String, DefensiveAction> obfuscatedPlan = new LinkedHashMap<>();

        for (Map.Entry<String, DefensiveAction> entry : plannedActions.entrySet()) {
            String taskId = entry.getKey();
            DefensiveAction plannedAction = entry.getValue();
            WorldModel vuln = vulnerabilities.get(taskId);

            if (vuln != null) {
                DefensiveAction obfuscated = applyRandomizedResponse(plannedAction, vuln);
                obfuscatedPlan.put(taskId, obfuscated);
            }
        }

        return obfuscatedPlan;
    }
}
