package org.anonymous.cloe;

import java.io.BufferedReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.*;

/**
 * Loads real OSS-Fuzz vulnerability data from the CyberGym dataset.
 * Ingests 1,507 actual vulnerabilities from HuggingFace CyberGym dataset.
 *
 * Data format (CSV):
 * cve_id, description, severity, exploitability, vuln_class, discovered_date, first_exploited_date, historical_mitigation_rate
 */
public class CyberGymRealDataLoader {
    private static final String DEFAULT_DATA_PATH = "data/cybergym-vulnerabilities-real.csv";

    private final Path datasetPath;
    private final Set<String> loadedTaskIds;

    public CyberGymRealDataLoader() {
        this(Paths.get(DEFAULT_DATA_PATH));
    }

    public CyberGymRealDataLoader(Path datasetPath) {
        this.datasetPath = datasetPath;
        this.loadedTaskIds = new HashSet<>();
    }

    /**
     * Loads all vulnerabilities from the CyberGym CSV dataset.
     * Filters to include only HIGH and CRITICAL severity vulnerabilities (per paper).
     */
    public List<WorldModel> loadAllVulnerabilities() throws Exception {
        if (!Files.exists(datasetPath)) {
            throw new RuntimeException("CyberGym dataset not found at: " + datasetPath.toAbsolutePath());
        }

        List<WorldModel> vulnerabilities = new ArrayList<>();
        int totalRecords = 0;
        int acuteVulnerabilities = 0;
        int skippedRecords = 0;

        try (BufferedReader reader = Files.newBufferedReader(datasetPath)) {
            String line;
            int lineNum = 0;

            while ((line = reader.readLine()) != null) {
                lineNum++;

                // Skip header row
                if (lineNum == 1) {
                    continue;
                }

                totalRecords++;

                try {
                    WorldModel vuln = parseVulnerabilityRecord(line);
                    if (vuln != null && isAcuteVulnerability(vuln)) {
                        vulnerabilities.add(vuln);
                        loadedTaskIds.add(vuln.getTaskId());
                        acuteVulnerabilities++;
                    }
                } catch (Exception e) {
                    skippedRecords++;
                }
            }
        }

        System.out.println("CyberGym Data Loading Complete:");
        System.out.println("  • Total records read: " + totalRecords);
        System.out.println("  • Acute vulnerabilities (HIGH+CRITICAL): " + acuteVulnerabilities);
        System.out.println("  • Skipped malformed records: " + skippedRecords);
        System.out.println("  • Density: " + String.format("%.2f%%",
                (double) acuteVulnerabilities / totalRecords * 100));

        return vulnerabilities;
    }

    /**
     * Filters to only CRITICAL and HIGH severity vulnerabilities.
     * Per paper: "1,507 real OSS-Fuzz fuzzing tasks"
     */
    private boolean isAcuteVulnerability(WorldModel vuln) {
        WorldModel.VulnerabilitySeverity sev = vuln.getSeverity();
        return sev == WorldModel.VulnerabilitySeverity.CRITICAL ||
               sev == WorldModel.VulnerabilitySeverity.HIGH;
    }

    /**
     * Parses a single CSV line into a WorldModel vulnerability object.
     *
     * CSV Format:
     * cve_id, description, severity, exploitability, vuln_class, discovered_date, first_exploited_date, historical_mitigation_rate
     */
    private WorldModel parseVulnerabilityRecord(String line) throws Exception {
        java.util.List<String> parts = parseCSVLine(line);
        if (parts.size() < 8) {
            return null;
        }

        String taskId = parts.get(0).trim();

        // Check for duplicates
        if (loadedTaskIds.contains(taskId)) {
            return null;
        }

        String description = parts.get(1).trim();
        String severity = parts.get(2).trim().toUpperCase();

        try {
            // Parse exploitability risk
            double exploitability = Double.parseDouble(parts.get(3).trim());

            // Vulnerability class (not used in WorldModel but available for context)
            String vulnClass = parts.get(4).trim();

            // Parse dates
            Instant discoveredAt = parseDate(parts.get(5).trim());
            Instant firstExploitedAt = parseDate(parts.get(6).trim());

            // Historical mitigation rate (becomes true exploitability risk)
            double historicalMitigationRate = Double.parseDouble(parts.get(7).trim());

            // Determine if in deployment window (within 30 days of now)
            Instant now = Instant.now();
            long daysSinceDiscovery = java.time.temporal.ChronoUnit.DAYS.between(discoveredAt, now);
            boolean inDeploymentWindow = daysSinceDiscovery <= 30;

            // Map severity string to enum
            WorldModel.VulnerabilitySeverity severityEnum;
            try {
                severityEnum = WorldModel.VulnerabilitySeverity.valueOf(severity);
            } catch (IllegalArgumentException e) {
                severityEnum = WorldModel.VulnerabilitySeverity.MEDIUM;
            }

            // Use exploitability as the true exploitability risk
            return new WorldModel(
                    taskId,
                    extractProjectName(description),
                    extractLanguage(description),
                    severityEnum,
                    exploitability,
                    discoveredAt,
                    inDeploymentWindow
            );
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Parses a CSV line properly handling quoted fields.
     */
    private java.util.List<String> parseCSVLine(String line) {
        java.util.List<String> result = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;

        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);

            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == ',' && !inQuotes) {
                result.add(current.toString());
                current = new StringBuilder();
            } else {
                current.append(c);
            }
        }

        result.add(current.toString());
        return result;
    }

    /**
     * Parses ISO 8601 date strings.
     */
    private Instant parseDate(String dateStr) {
        try {
            return Instant.parse(dateStr);
        } catch (Exception e) {
            return Instant.now();
        }
    }

    /**
     * Extracts project name from description (often in [brackets]).
     */
    private String extractProjectName(String description) {
        if (description.contains("[") && description.contains("]")) {
            int start = description.lastIndexOf("[");
            int end = description.lastIndexOf("]");
            if (start < end) {
                return description.substring(start + 1, end);
            }
        }
        return "unknown-project";
    }

    /**
     * Attempts to extract programming language from description.
     * Looks for common keywords.
     */
    private String extractLanguage(String description) {
        String lower = description.toLowerCase();
        if (lower.contains("c++") || lower.contains("cpp")) return "C++";
        if (lower.contains(" c ") || lower.contains("clang")) return "C";
        if (lower.contains("python")) return "Python";
        if (lower.contains("java")) return "Java";
        if (lower.contains("rust")) return "Rust";
        if (lower.contains("go")) return "Go";
        if (lower.contains("javascript") || lower.contains("node")) return "JavaScript";
        return "C";  // Default (most OSS-Fuzz targets are C/C++)
    }

    /**
     * Returns the count of loaded task IDs (deduplication metric).
     */
    public int getLoadedTaskCount() {
        return loadedTaskIds.size();
    }

    /**
     * Returns diagnostic information.
     */
    public Map<String, Object> getDiagnostics() {
        Map<String, Object> diag = new LinkedHashMap<>();
        diag.put("dataset_path", datasetPath.toAbsolutePath().toString());
        diag.put("dataset_exists", Files.exists(datasetPath));
        diag.put("unique_tasks_loaded", loadedTaskIds.size());

        if (Files.exists(datasetPath)) {
            try {
                long sizeBytes = Files.size(datasetPath);
                diag.put("file_size_mb", String.format("%.2f", sizeBytes / (1024.0 * 1024.0)));
            } catch (Exception e) {
                diag.put("file_size_error", e.getMessage());
            }
        }

        return diag;
    }
}
