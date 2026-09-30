package org.anonymous.cloe;

import java.time.Instant;
import java.util.Objects;

/**
 * Represents a single vulnerability in the world model.
 * Captures both observable state (severity) and latent ground truth (true exploitability risk).
 */
public class WorldModel {
    private final String taskId;
    private final String projectName;
    private final String language;
    private final VulnerabilitySeverity severity;
    private final double trueExploitabilityRisk;
    private final Instant discoveryTime;
    private final boolean isInDeploymentWindow;

    public enum VulnerabilitySeverity {
        CRITICAL(0.95),
        HIGH(0.70),
        MEDIUM(0.40),
        LOW(0.10);

        private final double baseRisk;

        VulnerabilitySeverity(double baseRisk) {
            this.baseRisk = baseRisk;
        }

        public double getBaseRisk() {
            return baseRisk;
        }
    }

    public WorldModel(
            String taskId,
            String projectName,
            String language,
            VulnerabilitySeverity severity,
            double trueExploitabilityRisk,
            Instant discoveryTime,
            boolean isInDeploymentWindow) {
        this.taskId = taskId;
        this.projectName = projectName;
        this.language = language;
        this.severity = severity;
        this.trueExploitabilityRisk = Math.max(0.0, Math.min(1.0, trueExploitabilityRisk));
        this.discoveryTime = discoveryTime;
        this.isInDeploymentWindow = isInDeploymentWindow;
    }

    public String getTaskId() {
        return taskId;
    }

    public String getProjectName() {
        return projectName;
    }

    public String getLanguage() {
        return language;
    }

    public VulnerabilitySeverity getSeverity() {
        return severity;
    }

    public double getTrueExploitabilityRisk() {
        return trueExploitabilityRisk;
    }

    public Instant getDiscoveryTime() {
        return discoveryTime;
    }

    public boolean isInDeploymentWindow() {
        return isInDeploymentWindow;
    }

    public double getRiskScore() {
        return trueExploitabilityRisk * severity.getBaseRisk();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WorldModel that = (WorldModel) o;
        return Objects.equals(taskId, that.taskId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(taskId);
    }

    @Override
    public String toString() {
        return "WorldModel{" +
                "taskId='" + taskId + '\'' +
                ", severity=" + severity +
                ", riskScore=" + String.format("%.4f", getRiskScore()) +
                '}';
    }
}
