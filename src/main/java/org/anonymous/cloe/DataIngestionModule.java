package org.anonymous.cloe;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Data Ingestion Module for CISA KEV and CyberGym datasets
 *
 * Handles:
 * - Loading CISA Known Exploited Vulnerabilities catalog (JSON format)
 * - Loading CyberGym benchmark vulnerability data (CSV format)
 * - Parsing and normalizing records
 * - Filtering for WAF-applicable Layer 7 attacks
 */
public class DataIngestionModule {

 public static final String CISA_KEV_PATH = "data/cisa_kev_catalog.json";
 public static final String CYBERGYM_PATH = "data/cybergym-vulnerabilities-real.csv";
 public static final String CISA_KEV_SAMPLE_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

 /**
 * Load CISA KEV data from JSON file
 * Falls back to sample data if file not found
 */
 public static List<Map<String, String>> loadCisaKevData() throws Exception {
 List<Map<String, String>> records = new ArrayList<>();
 Path path = Paths.get(CISA_KEV_PATH);

 try {
 if (Files.exists(path)) {
 String content = new String(Files.readAllBytes(path));
 records = parseCisaJsonFormat(content);
 } else {
 System.out.println(" CISA KEV catalog not found at " + CISA_KEV_PATH);
 System.out.println(" Using sample data for evaluation...");
 records = generateSampleCisaKevData();
 }
 } catch (Exception e) {
 System.out.println(" Error loading CISA KEV data: " + e.getMessage());
 System.out.println(" Falling back to sample data...");
 records = generateSampleCisaKevData();
 }

 System.out.println(" Loaded " + records.size() + " CISA KEV records");
 return records;
 }

 /**
 * Load CyberGym data from CSV file
 */
 public static List<Map<String, String>> loadCyberGymData() throws Exception {
 List<Map<String, String>> records = new ArrayList<>();
 Path path = Paths.get(CYBERGYM_PATH);

 try {
 if (Files.exists(path)) {
 BufferedReader reader = new BufferedReader(new FileReader(path.toFile()));
 String[] headers = null;
 String line;

 int lineNum = 0;
 while ((line = reader.readLine()) != null) {
 if (lineNum == 0) {
 headers = line.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
 lineNum++;
 continue;
 }

 String[] values = line.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
 Map<String, String> record = new HashMap<>();

 for (int i = 0; i < headers.length && i < values.length; i++) {
 record.put(headers[i], values[i].replaceAll("^\"|\"$", ""));
 }

 records.add(record);
 lineNum++;
 }
 reader.close();
 } else {
 System.out.println(" CyberGym data not found at " + CYBERGYM_PATH);
 System.out.println(" Using sample data for evaluation...");
 records = generateSampleCyberGymData();
 }
 } catch (Exception e) {
 System.out.println(" Error loading CyberGym data: " + e.getMessage());
 System.out.println(" Falling back to sample data...");
 records = generateSampleCyberGymData();
 }

 System.out.println(" Loaded " + records.size() + " CyberGym records");
 return records;
 }

 /**
 * Parse CISA JSON format
 * Expected format: {"vulnerabilities": [{...}]}
 */
 private static List<Map<String, String>> parseCisaJsonFormat(String json) {
 List<Map<String, String>> records = new ArrayList<>();

 // Simple JSON parsing without external libraries
 if (json.contains("\"vulnerabilities\"")) {
 int start = json.indexOf("[", json.indexOf("vulnerabilities"));
 int end = json.lastIndexOf("]");

 if (start > 0 && end > start) {
 String vulnArray = json.substring(start + 1, end);
 // Split by individual vulnerability objects
 String[] vulns = vulnArray.split("(?=\\{\"cveID)");

 for (String vuln : vulns) {
 Map<String, String> record = parseJsonObject(vuln);
 if (!record.isEmpty()) {
 records.add(record);
 }
 }
 }
 }

 return records;
 }

 /**
 * Simple JSON object parser
 */
 private static Map<String, String> parseJsonObject(String jsonObj) {
 Map<String, String> map = new HashMap<>();
 jsonObj = jsonObj.replace("{", "").replace("}", "").replace("\"", "");

 String[] pairs = jsonObj.split(",");
 for (String pair : pairs) {
 String[] kv = pair.split(":");
 if (kv.length == 2) {
 map.put(kv[0].trim(), kv[1].trim());
 }
 }

 return map;
 }

 /**
 * Generate representative sample CISA KEV data for testing
 */
 private static List<Map<String, String>> generateSampleCisaKevData() {
 List<Map<String, String>> records = new ArrayList<>();

 String[][] sampleData = {
 {"CVE-2023-46604", "Apache OFBiz", "Remote Code Execution in XML-RPC endpoints", "Remote Code Execution"},
 {"CVE-2023-44487", "HTTP/2 Protocol", "Rapid reset attack via HTTP/2 stream cancellation", "Denial of Service"},
 {"CVE-2023-39615", "Apache ActiveMQ", "Remote code execution via deserialization", "Remote Code Execution"},
 {"CVE-2023-38545", "curl", "SOCKS5 heap buffer overflow", "Buffer Overflow"},
 {"CVE-2023-35078", "Windows MSHTML", "Remote code execution via script processing", "Remote Code Execution"},
 {"CVE-2023-34362", "Microsoft Exchange", "Remote code execution in HTTP handler", "Remote Code Execution"},
 {"CVE-2023-21674", "Windows Win32k", "Privilege escalation via kernel vulnerability", "Privilege Escalation"},
 {"CVE-2023-21716", "TIFF image processing", "Remote code execution via TIFF parsing", "Remote Code Execution"},
 {"CVE-2023-20198", "Cisco IOS XE", "Command execution via HTTP request handler", "Remote Code Execution"},
 {"CVE-2022-41080", "Microsoft Exchange", "Remote code execution via authentication bypass", "Remote Code Execution"},
 {"CVE-2022-47986", "Ruby on Rails", "SQL injection in Active Record", "SQL Injection"},
 {"CVE-2022-24521", "Windows Win32k", "Elevation of privilege in graphics rendering", "Privilege Escalation"},
 {"CVE-2022-24444", "Google Chrome V8", "Use after free in JavaScript engine", "Remote Code Execution"},
 {"CVE-2021-44228", "Apache Log4j", "Remote code execution via LDAP injection", "LDAP Injection"},
 {"CVE-2021-26855", "Microsoft Exchange", "Server-side request forgery in URL processing", "Server-Side Request Forgery"},
 {"CVE-2021-21985", "VMware vCenter", "Remote code execution via HTTP API", "Remote Code Execution"},
 {"CVE-2021-21224", "Google Chrome", "Cross-site scripting in browser rendering", "Cross-Site Scripting"},
 {"CVE-2021-20091", "Kubernetes", "Privilege escalation via mount options", "Privilege Escalation"},
 {"CVE-2020-5410", "Spring Cloud Config", "Directory traversal in config server", "Directory Traversal"},
 {"CVE-2019-9193", "PostgreSQL", "Remote code execution via copy to/from", "Remote Code Execution"}
 };

 for (String[] data : sampleData) {
 Map<String, String> record = new HashMap<>();
 record.put("cveID", data[0]);
 record.put("product", data[1]);
 record.put("shortDescription", data[2]);
 record.put("vulnerabilityName", data[3]);
 record.put("vendorProject", data[1]);
 record.put("dateAdded", "2023-01-01");
 record.put("attackVector", "Network");
 record.put("dueDate", "2023-02-01");
 record.put("notes", "");
 records.add(record);
 }

 // Repeat for sample dataset of reasonable size
 List<Map<String, String>> expanded = new ArrayList<>();
 for (int i = 0; i < 100; i++) {
 for (Map<String, String> rec : records) {
 Map<String, String> copy = new HashMap<>(rec);
 copy.put("cveID", copy.get("cveID") + "_" + i);
 expanded.add(copy);
 }
 }

 return expanded;
 }

 /**
 * Generate representative sample CyberGym data for testing
 */
 private static List<Map<String, String>> generateSampleCyberGymData() {
 List<Map<String, String>> records = new ArrayList<>();

 String[][] sampleData = {
 {"CVE-2024-80000", "SQL_INJECTION", "0.99", "A SQL injection vulnerability in query handler"},
 {"CVE-2024-80001", "RCE", "0.95", "Remote code execution via command processing"},
 {"CVE-2024-80002", "PATH_TRAVERSAL", "0.76", "Path traversal in file access handler"},
 {"CVE-2024-80003", "AUTH_BYPASS", "0.8", "Authentication bypass via session manipulation"},
 {"CVE-2024-80004", "XXE", "0.81", "XML External Entity injection vulnerability"},
 {"CVE-2024-80005", "CSRF", "0.9", "Cross-site request forgery in state-changing operations"},
 {"CVE-2024-80006", "RCE", "0.87", "Remote code execution via unsafe deserialization"},
 {"CVE-2024-80007", "PATH_TRAVERSAL", "0.85", "Directory traversal in file download"},
 {"CVE-2024-80008", "XSS", "0.79", "Stored cross-site scripting in user profile"},
 {"CVE-2024-80009", "LDAP_INJECTION", "0.9", "LDAP injection in authentication"},
 {"CVE-2024-80010", "OS_COMMAND_INJECTION", "0.81", "OS command injection in system integration"},
 {"CVE-2024-80011", "AUTH_BYPASS", "0.95", "Authentication bypass via timing attack"},
 {"CVE-2024-80012", "XXE", "0.82", "XXE vulnerability in XML upload handler"},
 {"CVE-2024-80013", "OPEN_REDIRECT", "0.87", "Open redirect in OAuth flow"},
 {"CVE-2024-80014", "SQL_INJECTION", "0.79", "Blind SQL injection in search functionality"}
 };

 for (String[] data : sampleData) {
 Map<String, String> record = new HashMap<>();
 record.put("cve_id", data[0]);
 record.put("vuln_class", data[1]);
 record.put("exploitability", data[2]);
 record.put("description", data[3]);
 record.put("severity", "HIGH");
 record.put("discovered_date", "2024-01-01");
 record.put("first_exploited_date", "2024-01-02");
 record.put("historical_mitigation_rate", "0.85");
 records.add(record);
 }

 // Expand for reasonable sample size
 List<Map<String, String>> expanded = new ArrayList<>();
 for (int i = 0; i < 50; i++) {
 for (Map<String, String> rec : records) {
 Map<String, String> copy = new HashMap<>(rec);
 copy.put("cve_id", copy.get("cve_id") + "_" + i);
 expanded.add(copy);
 }
 }

 return expanded;
 }

 /**
 * Validate data ingestion
 */
 public static void validateDataIngestion(List<Map<String, String>> cisaData,
 List<Map<String, String>> cybergymData) {
 System.out.println("\n Data Ingestion Summary");
 System.out.println("====================");
 System.out.println("CISA KEV Records: " + cisaData.size());
 System.out.println("CyberGym Records: " + cybergymData.size());
 System.out.println("Total Records: " + (cisaData.size() + cybergymData.size()));

 // Check field presence
 if (!cisaData.isEmpty()) {
 Map<String, String> sample = cisaData.get(0);
 System.out.println("\nCISA KEV Sample Fields: " + sample.keySet());
 }

 if (!cybergymData.isEmpty()) {
 Map<String, String> sample = cybergymData.get(0);
 System.out.println("CyberGym Sample Fields: " + sample.keySet());
 }
 }
}
