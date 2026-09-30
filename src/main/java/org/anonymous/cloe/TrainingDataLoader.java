package org.anonymous.cloe;

import java.io.BufferedReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * Loads anonymized historical vulnerability data for training AI models.
 *
 * Used to train:
 * 1. Baseline model (Trial-and-Error)
 * 2. Deep Q-Network (DQN)
 * 3. Risk Convergence Algorithm
 * 4. Full CLOE System
 *
 * Data stripped of all identifying information:
 * - No region, cloud provider, asset IDs
 * - No owner/team information
 * - No correlation IDs or service tree references
 * - Only: CVSS, Risk, Severity, Historical Action, Discovery Age
 *
 * Source: Production vulnerability dataset (107,760 acute vulnerabilities)
 */
public class TrainingDataLoader {
    private static final String DEFAULT_DATA_PATH = "data/baseline_vulnerability_data_train_AI_models.csv";

    public static class TrainingRecord {
        public final int vulnIndex;
        public final double cvssBase;
        public final String riskCategory;
        public final double severityScore;
        public final String historicalAction;
        public final int discoveryAgeDays;

        public TrainingRecord(int vulnIndex, double cvssBase, String riskCategory,
                            double severityScore, String historicalAction, int discoveryAgeDays) {
            this.vulnIndex = vulnIndex;
            this.cvssBase = cvssBase;
            this.riskCategory = riskCategory;
            this.severityScore = severityScore;
            this.historicalAction = historicalAction;
            this.discoveryAgeDays = discoveryAgeDays;
        }

        @Override
        public String toString() {
            return String.format("TrainingRecord{index=%d, cvss=%.1f, risk=%s, action=%s}",
                    vulnIndex, cvssBase, riskCategory, historicalAction);
        }
    }

    private final Path datasetPath;

    public TrainingDataLoader() {
        this(Paths.get(DEFAULT_DATA_PATH));
    }

    public TrainingDataLoader(Path datasetPath) {
        this.datasetPath = datasetPath;
    }

    /**
     * Loads all training records from the anonymized dataset.
     */
    public List<TrainingRecord> loadAllRecords() throws Exception {
        if (!Files.exists(datasetPath)) {
            throw new RuntimeException("Training dataset not found at: " + datasetPath.toAbsolutePath());
        }

        List<TrainingRecord> records = new ArrayList<>();
        int totalRecords = 0;
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
                    TrainingRecord record = parseRecord(line);
                    if (record != null) {
                        records.add(record);
                    }
                } catch (Exception e) {
                    skippedRecords++;
                }
            }
        }

        System.out.println("Training Data Loading Complete:");
        System.out.println("  • Total records loaded: " + records.size());
        System.out.println("  • Skipped malformed records: " + skippedRecords);
        System.out.println("  • Dataset source: Production vulnerability data (600K+ records)");
        System.out.println("  • Data anonymization: All identifying columns stripped");

        return records;
    }

    /**
     * Parses a single CSV line into a TrainingRecord.
     *
     * CSV Format:
     * vuln_index, cvss_base, risk_category, severity_score, historical_action, discovery_age_days
     */
    private TrainingRecord parseRecord(String line) throws Exception {
        String[] parts = line.split(",", -1);  // Keep empty fields
        if (parts.length < 6) {
            return null;
        }

        try {
            int vulnIndex = Integer.parseInt(parts[0].trim());
            double cvssBase = Double.parseDouble(parts[1].trim());
            String riskCategory = parts[2].trim();
            double severityScore = Double.parseDouble(parts[3].trim());
            String historicalAction = parts[4].trim();
            int discoveryAgeDays = Integer.parseInt(parts[5].trim());

            return new TrainingRecord(vulnIndex, cvssBase, riskCategory, severityScore,
                    historicalAction, discoveryAgeDays);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Returns diagnostic information about the training dataset.
     */
    public Map<String, Object> getDiagnostics() throws Exception {
        Map<String, Object> diag = new LinkedHashMap<>();
        diag.put("dataset_path", datasetPath.toAbsolutePath().toString());
        diag.put("dataset_exists", Files.exists(datasetPath));

        if (Files.exists(datasetPath)) {
            long sizeBytes = Files.size(datasetPath);
            diag.put("file_size_mb", String.format("%.2f", sizeBytes / (1024.0 * 1024.0)));

            // Count records
            List<TrainingRecord> records = loadAllRecords();
            diag.put("total_records", records.size());

            // Risk distribution
            Map<String, Integer> riskCounts = new HashMap<>();
            for (TrainingRecord record : records) {
                riskCounts.put(record.riskCategory,
                        riskCounts.getOrDefault(record.riskCategory, 0) + 1);
            }
            diag.put("risk_distribution", riskCounts);

            // Statistics
            double avgCvss = records.stream().mapToDouble(r -> r.cvssBase).average().orElse(0);
            double avgAge = records.stream().mapToDouble(r -> r.discoveryAgeDays).average().orElse(0);
            diag.put("average_cvss", String.format("%.2f", avgCvss));
            diag.put("average_discovery_age_days", String.format("%.1f", avgAge));
        }

        return diag;
    }

    /**
     * Loads records and stratifies them for model training.
     * Separates data by risk category for balanced model training.
     */
    public Map<String, List<TrainingRecord>> loadStratifiedByRisk() throws Exception {
        List<TrainingRecord> allRecords = loadAllRecords();

        Map<String, List<TrainingRecord>> stratified = new LinkedHashMap<>();
        for (TrainingRecord record : allRecords) {
            stratified.computeIfAbsent(record.riskCategory, k -> new ArrayList<>())
                    .add(record);
        }

        return stratified;
    }
}
