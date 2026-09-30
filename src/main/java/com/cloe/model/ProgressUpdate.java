package com.cloe.model;

import com.google.gson.JsonObject;

public class ProgressUpdate {

    private String stage;
    private String status;
    private String startTime;
    private StageProgress stage1;
    private StageProgress stage2;
    private StageProgress stage3;

    public ProgressUpdate() {
        this.stage1 = new StageProgress();
        this.stage2 = new StageProgress();
        this.stage3 = new StageProgress();
    }

    public String toJson() {
        JsonObject json = new JsonObject();
        json.addProperty("stage", stage);
        json.addProperty("status", status);
        json.addProperty("startTime", startTime);
        json.add("stage1", stage1.toJsonObject());
        json.add("stage2", stage2.toJsonObject());
        json.add("stage3", stage3.toJsonObject());
        return json.toString();
    }

    // Getters and setters
    public String getStage() { return stage; }
    public void setStage(String stage) { this.stage = stage; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getStartTime() { return startTime; }
    public void setStartTime(String startTime) { this.startTime = startTime; }

    public StageProgress getStage1() { return stage1; }
    public void setStage1(StageProgress stage1) { this.stage1 = stage1; }

    public StageProgress getStage2() { return stage2; }
    public void setStage2(StageProgress stage2) { this.stage2 = stage2; }

    public StageProgress getStage3() { return stage3; }
    public void setStage3(StageProgress stage3) { this.stage3 = stage3; }

    public static class StageProgress {
        private String status;
        private int progress;
        private int loaded;
        private int wafApplicable;
        private double rate;
        private int processed;
        private int validation;
        private int day;
        private int attempts;
        private int blocked;

        public JsonObject toJsonObject() {
            JsonObject json = new JsonObject();
            json.addProperty("status", status);
            json.addProperty("progress", progress);
            json.addProperty("loaded", loaded);
            json.addProperty("wafApplicable", wafApplicable);
            json.addProperty("rate", rate);
            json.addProperty("processed", processed);
            json.addProperty("validation", validation);
            json.addProperty("day", day);
            json.addProperty("attempts", attempts);
            json.addProperty("blocked", blocked);
            return json;
        }

        // Getters and setters
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        public int getProgress() { return progress; }
        public void setProgress(int progress) { this.progress = progress; }
    }

}
