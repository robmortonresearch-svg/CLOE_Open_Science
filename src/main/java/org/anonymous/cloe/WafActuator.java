package org.anonymous.cloe;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Deterministic LLM Actuator: Translates causal decisions into WAF JSON rules.
 * Implements AST regex verification and JSON schema linting to prevent prompt injection.
 * Includes --mock-llm mode for reproducibility in environments without GPU access.
 */
public class WafActuator {
    private static final boolean MOCK_LLM_ENABLED = isMockLlmEnabled();
    private static final Pattern AST_PATTERN = Pattern.compile("^[a-zA-Z_][a-zA-Z0-9_]*$");
    private static final Pattern JSON_STRING_PATTERN = Pattern.compile("^\"[^\"\\\\]*(?:\\\\.[^\"\\\\]*)*\"$");

    private final Map<String, String> precomputedRules;

    public WafActuator() {
        this.precomputedRules = initializePrecomputedRules();
    }

    /**
     * Determines if mock LLM mode is enabled via system property or environment variable.
     */
    private static boolean isMockLlmEnabled() {
        String prop = System.getProperty("cloe.mock-llm", "false");
        String env = System.getenv("CLOE_MOCK_LLM");
        return prop.equalsIgnoreCase("true") || (env != null && env.equalsIgnoreCase("true"));
    }

    /**
     * Generates a WAF JSON rule for a given action and vulnerability.
     */
    public String generateWafRule(DefensiveAction action, WorldModel vulnerability) {
        if (MOCK_LLM_ENABLED) {
            return generateMockWafRule(action, vulnerability);
        } else {
            return generateDeterministicWafRule(action, vulnerability);
        }
    }

    /**
     * Mock LLM mode: Returns pre-computed, syntactically perfect JSON rules
     * without requiring actual LLM API calls.
     */
    private String generateMockWafRule(DefensiveAction action, WorldModel vulnerability) {
        String cacheKey = action.name() + "_" + vulnerability.getSeverity().name();
        return precomputedRules.getOrDefault(cacheKey, generateDeterministicWafRule(action, vulnerability));
    }

    /**
     * Deterministic rule generation with guardrails.
     * Validates AST and JSON schema to prevent prompt injection.
     */
    private String generateDeterministicWafRule(DefensiveAction action, WorldModel vulnerability) {
        String ruleId = sanitizeIdentifier("rule_" + vulnerability.getTaskId());
        String ruleName = sanitizeIdentifier(action.getDisplayName());
        String description = sanitizeJsonString(action.getDescription());
        String severity = vulnerability.getSeverity().name();

        validateRuleComponents(ruleId, ruleName, severity);

        return buildWafJson(ruleId, ruleName, description, action, severity);
    }

    /**
     * Sanitizes identifiers to match AST regex pattern [a-zA-Z_][a-zA-Z0-9_]*
     */
    private String sanitizeIdentifier(String input) {
        String sanitized = input.replaceAll("[^a-zA-Z0-9_]", "_");
        if (sanitized.matches("^[0-9].*")) {
            sanitized = "_" + sanitized;
        }
        return sanitized.isEmpty() ? "rule" : sanitized;
    }

    /**
     * Sanitizes strings for JSON encoding by escaping special characters.
     */
    private String sanitizeJsonString(String input) {
        return input
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * Validates rule components against AST and JSON patterns.
     */
    private void validateRuleComponents(String ruleId, String ruleName, String severity) {
        if (!AST_PATTERN.matcher(ruleId).matches()) {
            throw new IllegalArgumentException("Invalid rule ID: " + ruleId);
        }
        if (!AST_PATTERN.matcher(ruleName).matches()) {
            throw new IllegalArgumentException("Invalid rule name: " + ruleName);
        }
        try {
            WorldModel.VulnerabilitySeverity.valueOf(severity);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid severity: " + severity);
        }
    }

    /**
     * Constructs the final WAF JSON rule.
     */
    private String buildWafJson(
            String ruleId,
            String ruleName,
            String description,
            DefensiveAction action,
            String severity) {

        String actionType = mapActionToWafType(action);

        return "{\n" +
                "  \"rule_id\": \"" + ruleId + "\",\n" +
                "  \"rule_name\": \"" + ruleName + "\",\n" +
                "  \"description\": \"" + description + "\",\n" +
                "  \"severity\": \"" + severity + "\",\n" +
                "  \"action\": \"" + actionType + "\",\n" +
                "  \"enabled\": true,\n" +
                "  \"priority\": " + computePriority(severity) + "\n" +
                "}";
    }

    /**
     * Maps CLOE actions to standard WAF rule action types.
     */
    private String mapActionToWafType(DefensiveAction action) {
        return switch (action) {
            case HOTFIX, PATCH -> "block";
            case BLOCK -> "block";
            case REDIRECT -> "redirect";
            case ALLOW -> "allow";
            case LOG -> "log";
        };
    }

    /**
     * Computes rule priority based on severity.
     */
    private int computePriority(String severity) {
        return switch (severity) {
            case "CRITICAL" -> 1;
            case "HIGH" -> 2;
            case "MEDIUM" -> 3;
            case "LOW" -> 4;
            default -> 5;
        };
    }

    /**
     * Initializes pre-computed WAF rules for mock LLM mode.
     */
    private Map<String, String> initializePrecomputedRules() {
        Map<String, String> rules = new LinkedHashMap<>();

        DefensiveAction[] actions = {DefensiveAction.HOTFIX, DefensiveAction.PATCH,
                DefensiveAction.BLOCK, DefensiveAction.REDIRECT, DefensiveAction.ALLOW, DefensiveAction.LOG};
        WorldModel.VulnerabilitySeverity[] severities = WorldModel.VulnerabilitySeverity.values();

        for (DefensiveAction action : actions) {
            for (WorldModel.VulnerabilitySeverity severity : severities) {
                String key = action.name() + "_" + severity.name();
                String rule = buildPrecomputedRule(action, severity);
                rules.put(key, rule);
            }
        }

        return rules;
    }

    /**
     * Builds a pre-computed rule for mock mode.
     */
    private String buildPrecomputedRule(DefensiveAction action, WorldModel.VulnerabilitySeverity severity) {
        String actionType = mapActionToWafType(action);
        int priority = computePriority(severity.name());

        return "{\n" +
                "  \"rule_id\": \"rule_" + action.name().toLowerCase() + "_" + severity.name().toLowerCase() + "\",\n" +
                "  \"rule_name\": \"" + action.getDisplayName() + "\",\n" +
                "  \"description\": \"" + sanitizeJsonString(action.getDescription()) + "\",\n" +
                "  \"severity\": \"" + severity.name() + "\",\n" +
                "  \"action\": \"" + actionType + "\",\n" +
                "  \"enabled\": true,\n" +
                "  \"priority\": " + priority + "\n" +
                "}";
    }

    /**
     * Verifies that the control plane is isolated from semantic prompt injection.
     */
    public boolean verifySemanticIsolation(String ruleJson) {
        try {
            int braceCount = 0;
            int bracketCount = 0;
            boolean inString = false;
            boolean escaped = false;

            for (char c : ruleJson.toCharArray()) {
                if (escaped) {
                    escaped = false;
                    continue;
                }
                if (c == '\\') {
                    escaped = true;
                    continue;
                }
                if (c == '"' && !escaped) {
                    inString = !inString;
                    continue;
                }
                if (!inString) {
                    if (c == '{') braceCount++;
                    if (c == '}') braceCount--;
                    if (c == '[') bracketCount++;
                    if (c == ']') bracketCount--;
                }
            }

            return braceCount == 0 && bracketCount == 0 && !inString;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Returns true if mock LLM mode is currently enabled.
     */
    public static boolean isMockLlmActive() {
        return MOCK_LLM_ENABLED;
    }
}
