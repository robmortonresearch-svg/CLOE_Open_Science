package com.cloe.controller;

import com.cloe.service.SimulatorService;
import com.cloe.service.WAFRuleValidator;
import com.cloe.service.WAFRuleGenerator;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class CLOEController {

    private static final Logger logger = LoggerFactory.getLogger(CLOEController.class);

    @Autowired
    private SimulatorService simulatorService;

    @Autowired
    private WAFRuleValidator wafValidator;

    @Autowired
    private WAFRuleGenerator wafGenerator;

    private int lastOutputLength = 0;

    /**
     * Get progress status
     */
    @GetMapping("/progress")
    public ResponseEntity<String> getProgress() {
        JsonObject json = new JsonObject();
        json.addProperty("stage", simulatorService.getStatus());
        json.addProperty("status", simulatorService.isRunning() ? "running" : "idle");
        json.addProperty("startTime", System.currentTimeMillis());

        return ResponseEntity.ok(json.toString());
    }

    /**
     * Get simulation output
     */
    @GetMapping("/output")
    public ResponseEntity<Map<String, Object>> getOutput() {
        String output = simulatorService.getOutput();

        // Split output into lines and format as array of objects
        String[] lines = output.split("\n");
        java.util.List<Map<String, String>> outputLines = new java.util.ArrayList<>();

        for (String line : lines) {
            Map<String, String> lineObj = new HashMap<>();
            lineObj.put("text", line);
            outputLines.add(lineObj);
        }

        Map<String, Object> response = new HashMap<>();
        response.put("output", outputLines);
        response.put("length", lines.length);

        return ResponseEntity.ok(response);
    }

    /**
     * Get report (markdown file)
     */
    @GetMapping("/report")
    public ResponseEntity<String> getReport() {
        try {
            String reportPath = "./output/cisa_kev_cybergym_evaluation.md";
            String content = new String(Files.readAllBytes(Paths.get(reportPath)));
            return ResponseEntity.ok(content);
        } catch (IOException e) {
            logger.error("Error reading report", e);
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Start simulation
     */
    @PostMapping("/start-simulation")
    public ResponseEntity<Map<String, String>> startSimulation() {
        simulatorService.startSimulation();
        lastOutputLength = 0;

        Map<String, String> response = new HashMap<>();
        response.put("status", "simulation started");
        response.put("message", "CLOE three-stage evaluation has begun");

        return ResponseEntity.ok(response);
    }

    /**
     * Stop simulation
     */
    @PostMapping("/stop-simulation")
    public ResponseEntity<Map<String, String>> stopSimulation() {
        simulatorService.stopSimulation();

        Map<String, String> response = new HashMap<>();
        response.put("status", "simulation stopped");
        response.put("message", "CLOE evaluation has been paused");

        return ResponseEntity.ok(response);
    }

    /**
     * Clear output
     */
    @PostMapping("/clear-output")
    public ResponseEntity<Map<String, String>> clearOutput() {
        simulatorService.clearOutput();
        lastOutputLength = 0;

        Map<String, String> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", "Output cleared");

        return ResponseEntity.ok(response);
    }

    /**
     * Get status
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getStatus() {
        Map<String, Object> response = new HashMap<>();
        response.put("running", simulatorService.isRunning());
        response.put("status", simulatorService.getStatus());

        return ResponseEntity.ok(response);
    }

    /**
     * Validate WAF rule using local LLM
     */
    @PostMapping("/validate-waf-rule")
    public ResponseEntity<Map<String, Object>> validateWAFRule(@RequestBody String rule) {
        WAFRuleValidator.ValidationResult result = wafValidator.validateRule(rule);

        Map<String, Object> response = new HashMap<>();
        response.put("valid", result.valid);
        response.put("score", result.score);
        response.put("reasoning", result.reasoning);
        response.put("ollama_available", wafValidator.isOllamaAvailable());

        return ResponseEntity.ok(response);
    }

    /**
     * Generate WAF rule using local LLM
     */
    @PostMapping("/generate-waf-rule")
    public ResponseEntity<Map<String, Object>> generateWAFRule(
            @RequestParam String vulnerabilityType,
            @RequestParam(defaultValue = "0.7") double severity,
            @RequestParam(defaultValue = "0.7") double exploitability) {

        Map<String, Object> rule = wafGenerator.generateWAFRule(vulnerabilityType, severity, exploitability);

        Map<String, Object> response = new HashMap<>();
        response.put("rule", rule);
        response.put("ollama_available", wafGenerator.isAvailable());

        return ResponseEntity.ok(response);
    }

}
