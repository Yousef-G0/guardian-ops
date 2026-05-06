package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type RuntimeConfig struct {
	MonitoredProcess string `json:"monitored_process"`
	CheckInterval    int    `json:"check_interval_seconds"`
	GithubRepo       string `json:"github_repo"`
	GithubToken      string `json:"github_token"`
	WebhookURL       string `json:"webhook_url"`
}

type AnomalyDetection struct {
	Timestamp   time.Time `json:"timestamp"`
	AnomalyType string    `json:"anomaly_type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Details     string    `json:"details"`
	Action      string    `json:"action"`
}

type RollbackRequest struct {
	Reason     string    `json:"reason"`
	Timestamp  time.Time `json:"timestamp"`
	Anomalies  []AnomalyDetection `json:"anomalies"`
}

var (
	config           RuntimeConfig
	anomalyThreshold = 3
	anomalyCount     = 0
	knownPorts       = make(map[int]bool)
	baselineProcesses = make(map[string]bool)
)

func main() {
	log.Println(" Guardian-Ops - Runtime Agent Starting...")

	// Load configuration
	loadConfig()

	// Establish baseline
	log.Println(" Establishing baseline...")
	establishBaseline()

	// Start monitoring loop
	log.Printf("  Monitoring process: %s (interval: %ds)", 
		config.MonitoredProcess, config.CheckInterval)
	
	monitorLoop()
}

func loadConfig() {
	// Default configuration
	config = RuntimeConfig{
		MonitoredProcess: getEnvOrDefault("MONITORED_PROCESS", ""),
		CheckInterval:    getEnvIntOrDefault("CHECK_INTERVAL", 30),
		GithubRepo:       getEnvOrDefault("GITHUB_REPO", ""),
		GithubToken:      getEnvOrDefault("GITHUB_TOKEN", ""),
		WebhookURL:       getEnvOrDefault("WEBHOOK_URL", ""),
	}

	if config.MonitoredProcess == "" {
		log.Println(" No MONITORED_PROCESS set, monitoring entire system")
	}

	log.Printf(" Config loaded: repo=%s, interval=%ds", config.GithubRepo, config.CheckInterval)
}

func establishBaseline() {
	// Capture initial network state
	ports := getListeningPorts()
	for _, port := range ports {
		knownPorts[port] = true
	}
	log.Printf("   Baseline ports: %v", ports)

	// Capture running processes
	processes := getRunningProcesses()
	for _, proc := range processes {
		baselineProcesses[proc] = true
	}
	log.Printf("   Baseline processes: %d detected", len(baselineProcesses))
}

func monitorLoop() {
	ticker := time.NewTicker(time.Duration(config.CheckInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		anomalies := performChecks()
		
		if len(anomalies) > 0 {
			handleAnomalies(anomalies)
		}
	}
}

func performChecks() []AnomalyDetection {
	var anomalies []AnomalyDetection

	// 1. Check for reverse shells
	if revShell := detectReverseShell(); revShell != nil {
		anomalies = append(anomalies, *revShell)
	}

	// 2. Check for suspicious network activity
	if netAnom := detectSuspiciousNetwork(); netAnom != nil {
		anomalies = append(anomalies, *netAnom)
	}

	// 3. Check for process anomalies
	if procAnom := detectProcessAnomalies(); procAnom != nil {
		anomalies = append(anomalies, *procAnom)
	}

	// 4. Check for file system modifications
	if fileAnom := detectFileModifications(); fileAnom != nil {
		anomalies = append(anomalies, *fileAnom)
	}

	return anomalies
}

func detectReverseShell() *AnomalyDetection {
	// Check for common reverse shell patterns in network connections
	cmd := exec.Command("sh", "-c", "netstat -tunap 2>/dev/null || ss -tunap 2>/dev/null || echo ''")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	suspiciousPatterns := []string{
		"/bin/sh",
		"/bin/bash",
		"nc -e",
		"ncat",
		"python.*socket",
		"perl.*socket",
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		for _, pattern := range suspiciousPatterns {
			if matched, _ := regexp.MatchString(pattern, line); matched {
				return &AnomalyDetection{
					Timestamp:   time.Now(),
					AnomalyType: "REVERSE_SHELL",
					Severity:    "CRITICAL",
					Description: "Potential reverse shell detected",
					Details:     fmt.Sprintf("Suspicious process: %s", line),
					Action:      "ROLLBACK_REQUIRED",
				}
			}
		}
	}

	return nil
}

func detectSuspiciousNetwork() *AnomalyDetection {
	currentPorts := getListeningPorts()
	
	// Find new ports not in baseline
	var newPorts []int
	for _, port := range currentPorts {
		if !knownPorts[port] {
			newPorts = append(newPorts, port)
		}
	}

	if len(newPorts) > 0 {
		// Check if it's a suspicious port
		for _, port := range newPorts {
			if isSuspiciousPort(port) {
				return &AnomalyDetection{
					Timestamp:   time.Now(),
					AnomalyType: "SUSPICIOUS_PORT",
					Severity:    "HIGH",
					Description: "New suspicious port opened",
					Details:     fmt.Sprintf("Port %d opened (not in baseline)", port),
					Action:      "INVESTIGATE",
				}
			}
		}

		// Too many new ports
		if len(newPorts) >= 5 {
			return &AnomalyDetection{
				Timestamp:   time.Now(),
				AnomalyType: "PORT_SCAN",
				Severity:    "HIGH",
				Description: "Multiple new ports opened",
				Details:     fmt.Sprintf("New ports: %v", newPorts),
				Action:      "INVESTIGATE",
			}
		}
	}

	return nil
}

func detectProcessAnomalies() *AnomalyDetection {
	processes := getRunningProcesses()
	
	suspiciousProcesses := []string{
		"cryptominer",
		"xmrig",
		"minerd",
		"cgminer",
		"nc -l",
		"ncat -l",
		"python -m SimpleHTTPServer",
		"python -m http.server",
	}

	for _, proc := range processes {
		procLower := strings.ToLower(proc)
		for _, suspicious := range suspiciousProcesses {
			if strings.Contains(procLower, suspicious) {
				return &AnomalyDetection{
					Timestamp:   time.Now(),
					AnomalyType: "SUSPICIOUS_PROCESS",
					Severity:    "CRITICAL",
					Description: "Suspicious process detected",
					Details:     fmt.Sprintf("Process: %s", proc),
					Action:      "ROLLBACK_REQUIRED",
				}
			}
		}
	}

	return nil
}

func detectFileModifications() *AnomalyDetection {
	// Check for modifications to critical files
	criticalFiles := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/root/.ssh/authorized_keys",
		"/home/*/.ssh/authorized_keys",
	}

	for _, file := range criticalFiles {
		if checkRecentModification(file) {
			return &AnomalyDetection{
				Timestamp:   time.Now(),
				AnomalyType: "CRITICAL_FILE_MODIFIED",
				Severity:    "CRITICAL",
				Description: "Critical system file modified",
				Details:     fmt.Sprintf("File: %s", file),
				Action:      "ROLLBACK_REQUIRED",
			}
		}
	}

	return nil
}

func handleAnomalies(anomalies []AnomalyDetection) {
	log.Printf("  %d anomalies detected!", len(anomalies))

	for _, anomaly := range anomalies {
		log.Printf("   [%s] %s: %s", 
			anomaly.Severity, 
			anomaly.AnomalyType, 
			anomaly.Description)
		log.Printf("      Details: %s", anomaly.Details)
	}

	// Check if rollback is required
	criticalCount := 0
	for _, anomaly := range anomalies {
		if anomaly.Severity == "CRITICAL" {
			criticalCount++
		}
	}

	if criticalCount > 0 {
		log.Printf(" CRITICAL ANOMALIES DETECTED - Initiating rollback...")
		triggerRollback(anomalies)
	} else {
		anomalyCount += len(anomalies)
		if anomalyCount >= anomalyThreshold {
			log.Printf(" Anomaly threshold exceeded - Initiating rollback...")
			triggerRollback(anomalies)
			anomalyCount = 0
		}
	}
}

func triggerRollback(anomalies []AnomalyDetection) {
	rollbackReq := RollbackRequest{
		Reason:    "Runtime anomalies detected",
		Timestamp: time.Now(),
		Anomalies: anomalies,
	}

	// Send to GitHub Actions via workflow_dispatch
	if config.GithubRepo != "" && config.GithubToken != "" {
		triggerGitHubWorkflow(rollbackReq)
	}

	// Send webhook notification
	if config.WebhookURL != "" {
		sendWebhook(rollbackReq)
	}

	// Log to file
	logRollback(rollbackReq)
}

func triggerGitHubWorkflow(req RollbackRequest) {
	// GitHub API endpoint for workflow_dispatch
	parts := strings.Split(config.GithubRepo, "/")
	if len(parts) != 2 {
		log.Println(" Invalid GitHub repo format")
		return
	}

	owner, repo := parts[0], parts[1]
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/workflows/rollback.yml/dispatches", 
		owner, repo)

	payload := map[string]interface{}{
		"ref": "main",
		"inputs": map[string]string{
			"reason":    req.Reason,
			"timestamp": req.Timestamp.Format(time.RFC3339),
			"severity":  "critical",
		},
	}

	jsonData, _ := json.Marshal(payload)
	
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf(" Failed to create request: %v", err)
		return
	}

	request.Header.Set("Authorization", "token "+config.GithubToken)
	request.Header.Set("Accept", "application/vnd.github.v3+json")
	request.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(request)
	if err != nil {
		log.Printf(" Failed to trigger workflow: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 204 {
		log.Println(" GitHub Actions rollback workflow triggered successfully")
	} else {
		body, _ := io.ReadAll(resp.Body)
		log.Printf(" Failed to trigger workflow (status %d): %s", resp.StatusCode, string(body))
	}
}

func sendWebhook(req RollbackRequest) {
	jsonData, _ := json.Marshal(req)
	
	resp, err := http.Post(config.WebhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf(" Webhook failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		log.Println(" Webhook notification sent")
	}
}

func logRollback(req RollbackRequest) {
	logFile := "/var/log/guardian-ops/rollbacks.log"
	
	// Create directory if needed
	os.MkdirAll("/var/log/guardian-ops", 0755)

	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to write rollback log: %v", err)
		return
	}
	defer f.Close()

	jsonData, _ := json.MarshalIndent(req, "", "  ")
	f.WriteString(string(jsonData) + "\n---\n")
	
	log.Printf(" Rollback logged to %s", logFile)
}

// Helper functions

func getListeningPorts() []int {
	var ports []int
	
	cmd := exec.Command("sh", "-c", "netstat -tuln 2>/dev/null | grep LISTEN || ss -tuln 2>/dev/null | grep LISTEN || echo ''")
	output, err := cmd.Output()
	if err != nil {
		return ports
	}

	re := regexp.MustCompile(`:(\d+)\s`)
	matches := re.FindAllStringSubmatch(string(output), -1)
	
	seen := make(map[int]bool)
	for _, match := range matches {
		if len(match) > 1 {
			var port int
			fmt.Sscanf(match[1], "%d", &port)
			if !seen[port] {
				ports = append(ports, port)
				seen[port] = true
			}
		}
	}

	return ports
}

func getRunningProcesses() []string {
	var processes []string
	
	cmd := exec.Command("ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		return processes
	}

	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}
		if line != "" {
			processes = append(processes, line)
		}
	}

	return processes
}

func isSuspiciousPort(port int) bool {
	// Common attack/malware ports
	suspiciousPorts := []int{
		4444,  // Metasploit default
		5555,  // Android Debug Bridge
		6667,  // IRC
		31337, // Back Orifice
		12345, // NetBus
		1337,  // Common hacker port
		6666,  // IRC
		7777,  // Common backdoor
	}

	for _, sp := range suspiciousPorts {
		if port == sp {
			return true
		}
	}

	return false
}

func checkRecentModification(filePath string) bool {
	// Expand wildcards
	matches, err := filepath.Glob(filePath)
	if err != nil || len(matches) == 0 {
		return false
	}

	for _, file := range matches {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}

		// Check if modified in last 60 seconds
		if time.Since(info.ModTime()) < 60*time.Second {
			return true
		}
	}

	return false
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var intVal int
		fmt.Sscanf(value, "%d", &intVal)
		return intVal
	}
	return defaultValue
}
