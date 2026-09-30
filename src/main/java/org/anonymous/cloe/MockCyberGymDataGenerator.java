package org.anonymous.cloe;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * Generates mock CyberGym data: 1,507 simulated OSS-Fuzz vulnerability tasks.
 * Produces realistic vulnerability distributions matching real-world OSS-Fuzz findings.
 */
public class MockCyberGymDataGenerator {
    private static final int TOTAL_VULNERABILITIES = 1_507;
    private static final String[] PROJECTS = {
            "openssl", "libxml2", "curl", "gzip", "sqlite", "protobuf",
            "libjpeg", "libpng", "zlib", "freetype", "harfbuzz", "icu",
            "openvpn", "openssh", "bind", "httpd", "nginx", "postgresql",
            "mysql", "redis", "mongodb", "elasticsearch", "kafka", "rabbitmq"
    };

    private static final String[] LANGUAGES = {
            "C", "C++", "Java", "Python", "Go", "Rust", "JavaScript", "TypeScript"
    };

    private static final double[] SEVERITY_DISTRIBUTION = {
            0.15,   // CRITICAL (15%)
            0.25,   // HIGH     (25%)
            0.35,   // MEDIUM   (35%)
            0.25    // LOW      (25%)
    };

    private final Random random;
    private final Instant baseTime;

    public MockCyberGymDataGenerator() {
        this.random = new Random(42);
        this.baseTime = Instant.now().minus(365, ChronoUnit.DAYS);
    }

    /**
     * Generates all 1,507 mock vulnerabilities.
     */
    public List<WorldModel> generateAllVulnerabilities() {
        List<WorldModel> vulnerabilities = new ArrayList<>();

        for (int i = 0; i < TOTAL_VULNERABILITIES; i++) {
            vulnerabilities.add(generateVulnerability(i));
        }

        return vulnerabilities;
    }

    /**
     * Generates a single mock vulnerability.
     */
    private WorldModel generateVulnerability(int index) {
        String taskId = String.format("OSS-FUZZ-%06d", index + 1);
        String project = PROJECTS[random.nextInt(PROJECTS.length)];
        String language = LANGUAGES[random.nextInt(LANGUAGES.length)];

        WorldModel.VulnerabilitySeverity severity = sampleSeverity();
        double trueExploitabilityRisk = generateExploitabilityRisk(severity);

        Instant discoveryTime = baseTime.plus(random.nextLong(365 * 24), ChronoUnit.HOURS);
        boolean inDeploymentWindow = isInDeploymentWindow(discoveryTime);

        return new WorldModel(
                taskId,
                project,
                language,
                severity,
                trueExploitabilityRisk,
                discoveryTime,
                inDeploymentWindow
        );
    }

    /**
     * Samples a severity level according to real-world distribution.
     */
    private WorldModel.VulnerabilitySeverity sampleSeverity() {
        double roll = random.nextDouble();
        double cumulative = 0.0;

        for (int i = 0; i < SEVERITY_DISTRIBUTION.length; i++) {
            cumulative += SEVERITY_DISTRIBUTION[i];
            if (roll < cumulative) {
                return WorldModel.VulnerabilitySeverity.values()[i];
            }
        }

        return WorldModel.VulnerabilitySeverity.LOW;
    }

    /**
     * Generates true exploitability risk: samples from a distribution
     * biased toward the severity level but with realistic variance.
     */
    private double generateExploitabilityRisk(WorldModel.VulnerabilitySeverity severity) {
        double mean = severity.getBaseRisk();
        double variance = 0.15;
        double gaussian = random.nextGaussian() * variance;
        double risk = mean + gaussian;
        return Math.max(0.0, Math.min(1.0, risk));
    }

    /**
     * Determines if a vulnerability is in the 30-day deployment window.
     */
    private boolean isInDeploymentWindow(Instant discoveryTime) {
        Instant now = Instant.now();
        long daysSinceDiscovery = ChronoUnit.DAYS.between(discoveryTime, now);
        return daysSinceDiscovery <= 30;
    }

    /**
     * Returns the total count of generated vulnerabilities.
     */
    public int getTotalCount() {
        return TOTAL_VULNERABILITIES;
    }
}
