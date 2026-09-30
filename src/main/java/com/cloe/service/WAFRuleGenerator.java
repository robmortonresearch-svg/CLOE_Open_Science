package com.cloe.service;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Generates ModSecurity WAF rules using local Ollama LLM
 * Creates rules for specific vulnerability types detected during Risk Convergence
 */
@Service
public class WAFRuleGenerator {

    private static final Logger logger = LoggerFactory.getLogger(WAFRuleGenerator.class);
    private static final String OLLAMA_BASE_URL = "http://localhost:11434";
    private static final String DEFAULT_MODEL = "mistral";

    /**
     * Generate a WAF rule for a specific vulnerability type
     * @param vulnerabilityType Type of vulnerability (e.g., SQL_INJECTION, XSS, RCE)
     * @param severity Severity level 0-1
     * @param exploitability Exploitability 0-1
     * @return Generated WAF rule as JSON
     */
    public Map<String, Object> generateWAFRule(String vulnerabilityType, double severity, double exploitability) {
        try {
            String prompt = buildGenerationPrompt(vulnerabilityType, severity, exploitability);
            String response = callOllamaAPI(prompt);
            return parseGeneratedRule(response, vulnerabilityType);
        } catch (Exception e) {
            logger.warn("Error generating WAF rule with Ollama: {}", e.getMessage());
            return generateFallbackRule(vulnerabilityType, severity);
        }
    }

    /**
     * Generate a batch of rules for multiple vulnerabilities
     */
    public Map<String, Map<String, Object>> generateRulesBatch(java.util.List<Map<String, Object>> vulnerabilities) {
        Map<String, Map<String, Object>> rules = new HashMap<>();

        for (Map<String, Object> vuln : vulnerabilities) {
            String type = (String) vuln.get("type");
            Double severity = (Double) vuln.get("severity");
            Double exploitability = (Double) vuln.get("exploitability");

            Map<String, Object> rule = generateWAFRule(type, severity, exploitability);
            rules.put(type + "_" + System.nanoTime(), rule);
        }

        return rules;
    }

    /**
     * Build generation prompt for the LLM
     */
    private String buildGenerationPrompt(String vulnerabilityType, double severity, double exploitability) {
        return "Generate a ModSecurity WAF rule to block " + vulnerabilityType +
               " attacks.\n\n" +
               "Context:\n" +
               "- Vulnerability Type: " + vulnerabilityType + "\n" +
               "- Severity: " + String.format("%.2f", severity) + "/1.0\n" +
               "- Exploitability: " + String.format("%.2f", exploitability) + "/1.0\n\n" +
               "Response format: JSON with fields:\n" +
               "{\n" +
               "  \"rule_id\": \"900XXX\",\n" +
               "  \"message\": \"description\",\n" +
               "  \"pattern\": \"regex pattern\",\n" +
               "  \"action\": \"deny\" or \"block\",\n" +
               "  \"severity\": \"CRITICAL\",\n" +
               "  \"confidence\": 0-1,\n" +
               "  \"false_positive_risk\": 0-1\n" +
               "}\n\n" +
               "Create a minimal, focused rule that blocks the attack without false positives.";
    }

    /**
     * Call Ollama API to generate rule
     */
    private String callOllamaAPI(String prompt) throws Exception {
        URL url = new URL(OLLAMA_BASE_URL + "/api/generate");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(30000);

        JsonObject requestBody = new JsonObject();
        requestBody.addProperty("model", DEFAULT_MODEL);
        requestBody.addProperty("prompt", prompt);
        requestBody.addProperty("stream", false);
        requestBody.addProperty("temperature", 0.5); // Slightly higher for rule creativity

        try (OutputStream os = conn.getOutputStream()) {
            os.write(requestBody.toString().getBytes(StandardCharsets.UTF_8));
            os.flush();
        }

        StringBuilder response = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            String line;
            while ((line = br.readLine()) != null) {
                response.append(line);
            }
        }

        return response.toString();
    }

    /**
     * Parse LLM response into WAF rule
     */
    private Map<String, Object> parseGeneratedRule(String response, String vulnerabilityType) {
        try {
            JsonObject json = JsonParser.parseString(response).getAsJsonObject();
            String responseText = json.get("response").getAsString();

            int jsonStart = responseText.indexOf("{");
            int jsonEnd = responseText.lastIndexOf("}") + 1;

            if (jsonStart >= 0 && jsonEnd > jsonStart) {
                String jsonStr = responseText.substring(jsonStart, jsonEnd);
                JsonObject rule = JsonParser.parseString(jsonStr).getAsJsonObject();

                Map<String, Object> result = new HashMap<>();
                result.put("rule_id", rule.has("rule_id") ? rule.get("rule_id").getAsString() : "900001");
                result.put("message", rule.has("message") ? rule.get("message").getAsString() : "Block " + vulnerabilityType);
                result.put("pattern", rule.has("pattern") ? rule.get("pattern").getAsString() : ".*");
                result.put("action", rule.has("action") ? rule.get("action").getAsString() : "deny");
                result.put("severity", rule.has("severity") ? rule.get("severity").getAsString() : "HIGH");
                result.put("confidence", rule.has("confidence") ? rule.get("confidence").getAsDouble() : 0.85);
                result.put("false_positive_risk", rule.has("false_positive_risk") ? rule.get("false_positive_risk").getAsDouble() : 0.1);
                result.put("vulnerability_type", vulnerabilityType);
                result.put("generated_by", "ollama_" + DEFAULT_MODEL);

                return result;
            }
        } catch (Exception e) {
            logger.debug("Error parsing LLM rule response: {}", e.getMessage());
        }

        return generateFallbackRule(vulnerabilityType, 0.7);
    }

    /**
     * Generate fallback rule when LLM is unavailable
     */
    private Map<String, Object> generateFallbackRule(String vulnerabilityType, double severity) {
        Map<String, Object> rule = new HashMap<>();

        String ruleId = generateRuleId();
        String pattern = getPatternForType(vulnerabilityType);

        rule.put("rule_id", ruleId);
        rule.put("message", "Block " + vulnerabilityType + " attempts");
        rule.put("pattern", pattern);
        rule.put("action", "deny");
        rule.put("severity", severity > 0.7 ? "CRITICAL" : "HIGH");
        rule.put("confidence", 0.75);
        rule.put("false_positive_risk", 0.15);
        rule.put("vulnerability_type", vulnerabilityType);
        rule.put("generated_by", "fallback");

        return rule;
    }

    /**
     * Generate unique rule ID
     */
    private String generateRuleId() {
        int baseId = 900000;
        int random = (int) (Math.random() * 99999);
        return String.valueOf(baseId + random);
    }

    /**
     * Get regex pattern for vulnerability type
     */
    private String getPatternForType(String type) {
        return switch (type) {
            case "SQL_INJECTION" -> "(?i:union\\s+select|select\\s+from|insert\\s+into|delete\\s+from|drop\\s+table)";
            case "XSS" -> "(?i:<script|javascript:|onerror=|onload=)";
            case "RCE" -> "(?i:exec|system|passthru|shell_exec|cmd\\.exe)";
            case "PATH_TRAVERSAL" -> "(?:\\.\\./|\\.\\\\)";
            case "XXE" -> "(?i:<!ENTITY|SYSTEM|DOCTYPE)";
            case "LDAP_INJECTION" -> "(?i:\\*|\\||\\&)";
            case "AUTH_BYPASS" -> "(?i:admin|root|password=|or\\s*1=1)";
            case "CSRF" -> "(?i:csrf|token=|_token)";
            default -> ".*";
        };
    }

    /**
     * Check if Ollama is available
     */
    public boolean isAvailable() {
        try {
            URL url = new URL(OLLAMA_BASE_URL + "/api/tags");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(2000);
            int status = conn.getResponseCode();
            return status == 200;
        } catch (Exception e) {
            return false;
        }
    }
}
