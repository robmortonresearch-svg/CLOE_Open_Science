package org.anonymous.cloe;

import java.io.*;
import java.nio.file.*;
import com.google.gson.*;

/**
 * Writes real-time progress updates to JSON file for dashboard visualization
 */
public class ProgressWriter {
    private static final String PROGRESS_FILE = "/app/progress.json";
    private final JsonObject root;

    public ProgressWriter() {
        this.root = new JsonObject();
        this.root.addProperty("stage", 0);
        this.root.addProperty("status", "initializing");
        this.root.addProperty("startTime", System.currentTimeMillis());

        // Initialize stage objects
        this.root.add("stage1", createStageObject());
        this.root.add("stage2", createStageObject());
        this.root.add("stage3", createStageObject());
    }

    private JsonObject createStageObject() {
        JsonObject obj = new JsonObject();
        obj.addProperty("status", "pending");
        obj.addProperty("progress", 0);
        obj.add("updates", new JsonArray());
        return obj;
    }

    public void updateStage1(int loaded, int wafApplicable, int days, double rate) {
        JsonObject stage1 = root.getAsJsonObject("stage1");
        stage1.addProperty("loaded", loaded);
        stage1.addProperty("wafApplicable", wafApplicable);
        stage1.addProperty("days", days);
        stage1.addProperty("rate", rate);
        stage1.addProperty("progress", (days * 100) / 30);
        stage1.addProperty("status", days < 30 ? "running" : "complete");
        save();
    }

    public void startStage1() {
        root.getAsJsonObject("stage1").addProperty("status", "running");
        root.addProperty("stage", 1);
        save();
    }

    public void updateStage2(int processed, String queueStatus, int penalties, int validation) {
        JsonObject stage2 = root.getAsJsonObject("stage2");
        stage2.addProperty("processed", processed);
        stage2.addProperty("queueStatus", queueStatus);
        stage2.addProperty("penalties", penalties);
        stage2.addProperty("validation", validation);
        stage2.addProperty("progress", (processed * 100) / 2174);
        stage2.addProperty("status", processed < 2174 ? "running" : "complete");
        save();
    }

    public void startStage2() {
        root.getAsJsonObject("stage2").addProperty("status", "running");
        root.addProperty("stage", 2);
        save();
    }

    public void updateStage3(int day, int attempts, int blocked, double rate,
                           double lowVol, double midVol, double highVol) {
        JsonObject stage3 = root.getAsJsonObject("stage3");
        stage3.addProperty("day", day);
        stage3.addProperty("attempts", attempts);
        stage3.addProperty("blocked", blocked);
        stage3.addProperty("rate", rate);
        stage3.addProperty("lowVol", lowVol);
        stage3.addProperty("midVol", midVol);
        stage3.addProperty("highVol", highVol);
        stage3.addProperty("progress", (day * 100) / 30);
        stage3.addProperty("status", day < 30 ? "running" : "complete");
        save();
    }

    public void startStage3() {
        root.getAsJsonObject("stage3").addProperty("status", "running");
        root.add("stage3", new JsonObject());
        root.getAsJsonObject("stage3").add("rules", new JsonArray());
        root.addProperty("stage", 3);
        save();
    }

    public void addWAFRule(String rule) {
        JsonObject stage3 = root.getAsJsonObject("stage3");
        if (!stage3.has("rules")) {
            stage3.add("rules", new JsonArray());
        }
        stage3.getAsJsonArray("rules").add(rule);
        save();
    }

    public void addUpdate(int stageNum, String message) {
        String stageKey = "stage" + stageNum;
        JsonObject stage = root.getAsJsonObject(stageKey);
        if (!stage.has("updates")) {
            stage.add("updates", new JsonArray());
        }
        stage.getAsJsonArray("updates").add(message);
        save();
    }

    public void complete() {
        root.addProperty("stage", 99);
        root.addProperty("status", "complete");
        root.addProperty("endTime", System.currentTimeMillis());
        save();
    }

    private void save() {
        try {
            String json = new GsonBuilder().setPrettyPrinting().create().toJson(root);
            Files.write(Paths.get(PROGRESS_FILE), json.getBytes(),
                       StandardOpenOption.CREATE,
                       StandardOpenOption.WRITE,
                       StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException e) {
            System.err.println("Warning: Could not write progress file: " + e.getMessage());
        }
    }
}
