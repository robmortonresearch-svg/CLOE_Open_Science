package org.anonymous.cloe;

/**
 * Sample WAF Rules generated from CLOE defense actions
 * Shows actual JSON rules that would be deployed
 */
public class WAFRuleSamples {

    public static String generateSampleRule(DefensiveAction action, String vulnerabilityDescription, String severity) {
        return switch (action) {
            case BLOCK -> String.format(
                "{\n" +
                "  \"id\": \"rule_block_%d\",\n" +
                "  \"action\": \"BLOCK\",\n" +
                "  \"priority\": 1,\n" +
                "  \"severity\": \"%s\",\n" +
                "  \"description\": \"%s\",\n" +
                "  \"patterns\": [\n" +
                "    \"(union|select|insert|drop)\\\\s+(from|into|database|table)\"\n" +
                "  ],\n" +
                "  \"responseCode\": 403,\n" +
                "  \"responseBody\": \"Access Denied: Malicious Pattern Detected\"\n" +
                "}",
                System.currentTimeMillis() % 10000, severity, vulnerabilityDescription
            );

            case REDIRECT -> String.format(
                "{\n" +
                "  \"id\": \"rule_redirect_%d\",\n" +
                "  \"action\": \"REDIRECT\",\n" +
                "  \"priority\": 2,\n" +
                "  \"severity\": \"%s\",\n" +
                "  \"description\": \"%s\",\n" +
                "  \"patterns\": [\n" +
                "    \"\\\\.\\\\./(\\\\w+)/\\\\.\\\\./(bin|etc|usr|sys)\"\n" +
                "  ],\n" +
                "  \"redirectUrl\": \"https://internal-verification.local/challenge\",\n" +
                "  \"verifyTimeout\": 5000\n" +
                "}",
                System.currentTimeMillis() % 10000, severity, vulnerabilityDescription
            );

            case PATCH -> String.format(
                "{\n" +
                "  \"id\": \"rule_patch_%d\",\n" +
                "  \"action\": \"PATCH\",\n" +
                "  \"priority\": 3,\n" +
                "  \"severity\": \"%s\",\n" +
                "  \"description\": \"%s\",\n" +
                "  \"patches\": [\n" +
                "    \"s/vulnerable_function/patched_function/g\"\n" +
                "  ],\n" +
                "  \"validationHash\": \"sha256:abc123def456\"\n" +
                "}",
                System.currentTimeMillis() % 10000, severity, vulnerabilityDescription
            );

            case HOTFIX -> String.format(
                "{\n" +
                "  \"id\": \"rule_hotfix_%d\",\n" +
                "  \"action\": \"HOTFIX\",\n" +
                "  \"priority\": 0,\n" +
                "  \"severity\": \"%s\",\n" +
                "  \"description\": \"%s\",\n" +
                "  \"deploymentStrategy\": \"IMMEDIATE\",\n" +
                "  \"rollbackTrigger\": \"error_rate > 0.05\",\n" +
                "  \"estimatedDowntime\": \"0 seconds\"\n" +
                "}",
                System.currentTimeMillis() % 10000, severity, vulnerabilityDescription
            );

            case ALLOW -> String.format(
                "{\n" +
                "  \"id\": \"rule_allow_%d\",\n" +
                "  \"action\": \"ALLOW\",\n" +
                "  \"priority\": 5,\n" +
                "  \"severity\": \"%s\",\n" +
                "  \"description\": \"%s\",\n" +
                "  \"conditions\": [\n" +
                "    \"trustedSource == true\",\n" +
                "    \"encryptedChannel == true\"\n" +
                "  ],\n" +
                "  \"monitoring\": true\n" +
                "}",
                System.currentTimeMillis() % 10000, severity, vulnerabilityDescription
            );

            case LOG -> String.format(
                "{\n" +
                "  \"id\": \"rule_log_%d\",\n" +
                "  \"action\": \"LOG\",\n" +
                "  \"priority\": 6,\n" +
                "  \"severity\": \"%s\",\n" +
                "  \"description\": \"%s\",\n" +
                "  \"logLevel\": \"WARNING\",\n" +
                "  \"includePayload\": true,\n" +
                "  \"sendAlert\": \"%s\"\n" +
                "}",
                System.currentTimeMillis() % 10000, severity, vulnerabilityDescription,
                severity.equals("CRITICAL") ? "true" : "false"
            );
        };
    }

    public static void showSampleVulnerabilityProcessing() {
        String[] sampleVulns = {
            "SQL Injection in user input validation",
            "Path traversal in file upload handler",
            "Cross-site scripting in comment section"
        };

        System.out.println("\n[Sample Output] Vulnerability Processing & WAF Rule Generation:");
        System.out.println();

        for (int i = 0; i < Math.min(3, sampleVulns.length); i++) {
            String vuln = sampleVulns[i];
            DefensiveAction action = DefensiveAction.values()[i % DefensiveAction.values().length];
            String severity = (i == 0) ? "CRITICAL" : "HIGH";

            System.out.println("─────────────────────────────────────────────────────────────────");
            System.out.println(String.format("Vulnerability #%d: %s", i + 1, vuln));
            System.out.println(String.format("Severity: %s | Selected Action: %s", severity, action));
            System.out.println();
            System.out.println("Generated WAF Rule (JSON):");
            System.out.println(generateSampleRule(action, vuln, severity));
            System.out.println();
        }
    }
}
