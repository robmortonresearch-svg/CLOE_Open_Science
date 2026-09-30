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

/**
 * Validates WAF rules using a local Ollama LLM instance
 * Requires: Ollama running locally on http://localhost:11434
 */
@Service
public class WAFRuleValidator {

    private static final Logger logger = LoggerFactory.getLogger(WAFRuleValidator.class);
    private static final String OLLAMA_BASE_URL = "http://localhost:11434";
    private static final String DEFAULT_MODEL = "mistral"; // Fast & accurate

    /**
     * Validate a WAF rule using local LLM
     * @param rule The WAF rule to validate (JSON format)
     * @return Validation result with score and reasoning
     */
    public ValidationResult validateRule(String rule) {
        try {
            String prompt = buildValidationPrompt(rule);
            String response = callOllamaAPI(prompt);
            return parseValidationResponse(response);
        } catch (Exception e) {
            logger.warn("Error validating rule with Ollama: {}", e.getMessage());
            return new ValidationResult(false, 0.5, "LLM unavailable - using fallback validation");
        }
    }

    /**
     * Check if Ollama is available locally
     */
    public boolean isOllamaAvailable() {
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

    /**
     * Build a validation prompt for the LLM
     */
    private String buildValidationPrompt(String rule) {
        return "Validate this WAF rule for security effectiveness and operational safety:\n\n" +
               rule + "\n\n" +
               "Response format: JSON with fields {valid: boolean, score: 0-1, reasoning: string}\n" +
               "Score 1.0: Perfect rule. 0.5: Needs review. 0.0: Invalid rule.";
    }

    /**
     * Call Ollama API to validate rule
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
        requestBody.addProperty("temperature", 0.3); // Low temperature for consistency

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
     * Parse LLM response into validation result
     */
    private ValidationResult parseValidationResponse(String response) {
        try {
            JsonObject json = JsonParser.parseString(response).getAsJsonObject();
            String responseText = json.get("response").getAsString();

            // Extract JSON from response
            int jsonStart = responseText.indexOf("{");
            int jsonEnd = responseText.lastIndexOf("}") + 1;

            if (jsonStart >= 0 && jsonEnd > jsonStart) {
                String jsonStr = responseText.substring(jsonStart, jsonEnd);
                JsonObject result = JsonParser.parseString(jsonStr).getAsJsonObject();

                boolean valid = result.has("valid") && result.get("valid").getAsBoolean();
                double score = result.has("score") ? result.get("score").getAsDouble() : 0.5;
                String reasoning = result.has("reasoning") ? result.get("reasoning").getAsString() : "No reasoning provided";

                return new ValidationResult(valid, score, reasoning);
            }
        } catch (Exception e) {
            logger.debug("Error parsing LLM response: {}", e.getMessage());
        }

        return new ValidationResult(false, 0.5, "Could not parse LLM response");
    }

    /**
     * Validation result from LLM
     */
    public static class ValidationResult {
        public boolean valid;
        public double score; // 0.0 to 1.0
        public String reasoning;

        public ValidationResult(boolean valid, double score, String reasoning) {
            this.valid = valid;
            this.score = Math.min(1.0, Math.max(0.0, score));
            this.reasoning = reasoning;
        }

        public JsonObject toJson() {
            JsonObject json = new JsonObject();
            json.addProperty("valid", valid);
            json.addProperty("score", score);
            json.addProperty("reasoning", reasoning);
            return json;
        }
    }

}
