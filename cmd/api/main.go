package main

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ScanRequest represents the incoming scan request
type ScanRequest struct {
	RepoPath   string `json:"repo_path" binding:"required"`
	Branch     string `json:"branch"`
	CommitHash string `json:"commit_hash"`
}

// ScanResult contains the complete scan output
type ScanResult struct {
	Timestamp    time.Time       `json:"timestamp"`
	RepoPath     string          `json:"repo_path"`
	Branch       string          `json:"branch"`
	CommitHash   string          `json:"commit_hash"`
	RiskScore    int             `json:"risk_score"`
	RiskLevel    string          `json:"risk_level"`
	Passed       bool            `json:"passed"`
	Secrets      []SecretFinding `json:"secrets"`
	CVEs         []CVEFinding    `json:"cves"`
	CodeIssues   []CodeIssue     `json:"code_issues"`
	PolicyResult PolicyResult    `json:"policy_result"`
	Summary      string          `json:"summary"`
}

type SecretFinding struct {
	File       string  `json:"file"`
	Line       int     `json:"line"`
	Type       string  `json:"type"`
	Severity   string  `json:"severity"`
	Match      string  `json:"match"`
	Confidence float64 `json:"confidence"` // 0.0 - 1.0
}

type CVEFinding struct {
	Package     string `json:"package"`
	Severity    string `json:"severity"`
	CVE         string `json:"cve"`
	Description string `json:"description"`
	CVSS        float64 `json:"cvss"`
}

type CodeIssue struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type PolicyResult struct {
	Passed   bool     `json:"passed"`
	Violations []string `json:"violations"`
	Warnings   []string `json:"warnings"`
}

// Simple LRU Cache for scan results
type LRUCache struct {
	capacity int
	cache    map[string]*list.Element
	lru      *list.List
}

type cacheItem struct {
	key   string
	value *ScanResult
}

func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		cache:    make(map[string]*list.Element),
		lru:      list.New(),
	}
}

func (c *LRUCache) Get(key string) (*ScanResult, bool) {
	if elem, ok := c.cache[key]; ok {
		c.lru.MoveToFront(elem)
		return elem.Value.(*cacheItem).value, true
	}
	return nil, false
}

func (c *LRUCache) Put(key string, value *ScanResult) {
	if elem, ok := c.cache[key]; ok {
		c.lru.MoveToFront(elem)
		elem.Value.(*cacheItem).value = value
		return
	}
	
	elem := c.lru.PushFront(&cacheItem{key: key, value: value})
	c.cache[key] = elem
	
	if c.lru.Len() > c.capacity {
		elem = c.lru.Back()
		if elem != nil {
			delete(c.cache, elem.Value.(*cacheItem).key)
			c.lru.Remove(elem)
		}
	}
}

// Global cache instance
var scanCache = NewLRUCache(50) // Cache last 50 scans

// Security patterns to detect (upgraded with context-aware regex - Go-compatible)
var secretPatterns = map[string]*regexp.Regexp{
	"AWS_KEY":           regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"GITHUB_TOKEN":      regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`),
	"PRIVATE_KEY":       regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`),
	"GENERIC_API_KEY":   regexp.MustCompile(`(?i)api[_-]?key["\s:=]+[a-z0-9]{20,}`),
	"PASSWORD":          regexp.MustCompile(`(?i)password["\s:=]+[^"\s]{8,}`),
	"DATABASE_URL":      regexp.MustCompile(`(?i)(postgres|mysql|mongodb)://[^\s"']+`),
	"JWT_TOKEN":         regexp.MustCompile(`eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`),
	"SLACK_TOKEN":       regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`),
}

var dangerousCodePatterns = map[string]*regexp.Regexp{
	"EVAL":              regexp.MustCompile(`\beval\s*\(`),
	"EXEC":              regexp.MustCompile(`\bexec\s*\(|os\.exec|subprocess\.call`),
	"SHELL_INJECTION":   regexp.MustCompile(`os\.system|shell=True|/bin/(bash|sh)`),
	"SQL_INJECTION":     regexp.MustCompile(`execute\s*\(\s*["'].*%s|["']\s*\+\s*\w+\s*\+\s*["']`),
	"UNSAFE_DESERIALIZATION": regexp.MustCompile(`pickle\.loads|yaml\.load\(|eval\(|Marshal\.load`),
	"HARDCODED_IP":      regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
}

func main() {
	router := gin.Default()

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy", "service": "guardian-ops"})
	})

	// Main scan endpoint
	router.POST("/scan", handleScan)

	// Risk scoring endpoint
	router.POST("/risk-score", handleRiskScore)

	// Policy validation endpoint
	router.POST("/validate-policy", handlePolicyValidation)

	log.Println("  Guardian-Ops API starting on :8080")
	router.Run(":8080")
}

func handleScan(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Generate cache key from repo path and branch
	cacheKey := hashString(req.RepoPath + req.Branch + req.CommitHash)
	
	// Check cache first
	if cachedResult, found := scanCache.Get(cacheKey); found {
		log.Printf(" Cache hit for %s - returning cached result", req.RepoPath)
		c.JSON(200, cachedResult)
		return
	}

	log.Printf("Starting scan for: %s (branch: %s)", req.RepoPath, req.Branch)

	result := ScanResult{
		Timestamp:  time.Now(),
		RepoPath:   req.RepoPath,
		Branch:     req.Branch,
		CommitHash: req.CommitHash,
	}

	// 1. Scan for secrets
	log.Println("  → Scanning for secrets...")
	result.Secrets = scanSecrets(req.RepoPath)

	// 2. Scan for CVEs (dependencies)
	log.Println("  → Scanning dependencies for CVEs...")
	result.CVEs = scanCVEs(req.RepoPath)

	// 3. Scan code for dangerous patterns
	log.Println("  → Analyzing code patterns...")
	result.CodeIssues = scanCodePatterns(req.RepoPath)

	// 4. Calculate risk score
	log.Println("  → Calculating risk score...")
	result.RiskScore = calculateRiskScore(&result)
	result.RiskLevel = getRiskLevel(result.RiskScore)

	// 5. Apply policies
	log.Println("  → Applying security policies...")
	result.PolicyResult = applyPolicies(&result)

	// 6. Apply OPA policies if available
	log.Println("  → Evaluating OPA policies...")
	opaResult := evaluateOPAPolicies(&result)
	if opaResult != nil {
		// Merge OPA results with existing policies
		if !opaResult.Passed {
			result.PolicyResult.Passed = false
			result.PolicyResult.Violations = append(result.PolicyResult.Violations, opaResult.Violations...)
		}
		result.PolicyResult.Warnings = append(result.PolicyResult.Warnings, opaResult.Warnings...)
	}
	result.Passed = result.PolicyResult.Passed

	// 6. Detect anomalies
	log.Println("  → Detecting anomalies...")
	anomalies := detectAnomalies(result.Secrets)
	if len(anomalies) > 0 {
		result.PolicyResult.Warnings = append(result.PolicyResult.Warnings, anomalies...)
	}

	// 7. Generate summary
	result.Summary = generateSummary(&result)

	log.Printf("Scan complete - Risk: %s (%d/100) - Passed: %v", 
		result.RiskLevel, result.RiskScore, result.Passed)

	// Cache the result
	scanCache.Put(cacheKey, &result)

	c.JSON(200, result)
}

func scanSecrets(repoPath string) []SecretFinding {
	var findings []SecretFinding
	seenHashes := make(map[string]bool) // Deduplication

	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		// Skip binary files and common exclusions
		if shouldSkipFile(path) {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		lines := strings.Split(string(content), "\n")
		for lineNum, line := range lines {
			for patternType, regex := range secretPatterns {
				if regex.MatchString(line) {
					match := regex.FindString(line)
					
					//  SMART FILTER: Check context before flagging
					if isFalsePositive(line, match, patternType, path) {
						continue
					}
					
					// Deduplicate by hash
					hash := hashString(match)
					if seenHashes[hash] {
						continue
					}
					seenHashes[hash] = true

					// Calculate confidence score
					confidence := calculateConfidence(line, match, patternType)

					// Mask sensitive data
					maskedMatch := maskSecret(match)

					findings = append(findings, SecretFinding{
						File:       relativePath(repoPath, path),
						Line:       lineNum + 1,
						Type:       patternType,
						Severity:   getSeverityForSecret(patternType),
						Match:      maskedMatch,
						Confidence: confidence,
					})
				}
			}
		}
		return nil
	})

	if err != nil {
		log.Printf("Warning: secret scan error: %v", err)
	}

	return findings
}

func scanCVEs(repoPath string) []CVEFinding {
	var findings []CVEFinding

	// Check for common dependency files
	dependencyFiles := []string{
		"package.json",
		"requirements.txt",
		"go.mod",
		"Gemfile",
		"pom.xml",
	}

	for _, depFile := range dependencyFiles {
		fullPath := filepath.Join(repoPath, depFile)
		if _, err := os.Stat(fullPath); err == nil {
			log.Printf("    Found %s, checking for known CVEs...", depFile)
			
			// Simulate CVE scanning (in production, integrate with OSV/Snyk/Trivy)
			// For MVP, we'll do basic pattern matching
			findings = append(findings, simulateCVEScan(fullPath, depFile)...)
		}
	}

	return findings
}

func simulateCVEScan(filePath, fileName string) []CVEFinding {
	var findings []CVEFinding

	content, err := os.ReadFile(filePath)
	if err != nil {
		return findings
	}

	// Known vulnerable patterns (simplified for MVP)
	vulnPatterns := map[string]CVEFinding{
		"express.*3\\.":   {Package: "express", Severity: "HIGH", CVE: "CVE-2022-24999", CVSS: 7.5, Description: "express <4.17.3 - DoS vulnerability"},
		"lodash.*4\\.16": {Package: "lodash", Severity: "CRITICAL", CVE: "CVE-2021-23337", CVSS: 9.1, Description: "Prototype pollution"},
		"django.*2\\.":   {Package: "django", Severity: "HIGH", CVE: "CVE-2023-24580", CVSS: 7.5, Description: "SQL injection vulnerability"},
	}

	for pattern, cve := range vulnPatterns {
		if matched, _ := regexp.MatchString(pattern, string(content)); matched {
			findings = append(findings, cve)
		}
	}

	return findings
}

func scanCodePatterns(repoPath string) []CodeIssue {
	var issues []CodeIssue

	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || shouldSkipFile(path) {
			return err
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		lines := strings.Split(string(content), "\n")
		for lineNum, line := range lines {
			for issueType, regex := range dangerousCodePatterns {
				if regex.MatchString(line) {
					//  SMART: Check if this is a legitimate use case
					if isLegitimateCodePattern(line, issueType, path, lines, lineNum) {
						continue
					}
					
					issues = append(issues, CodeIssue{
						File:        relativePath(repoPath, path),
						Line:        lineNum + 1,
						Type:        issueType,
						Severity:    getSeverityForCodeIssue(issueType),
						Description: getDescriptionForCodeIssue(issueType),
					})
				}
			}
		}
		return nil
	})

	if err != nil {
		log.Printf("Warning: code scan error: %v", err)
	}

	return issues
}

//  SMART: Context-aware code pattern validation
func isLegitimateCodePattern(line, issueType, filepath string, allLines []string, lineNum int) bool {
	lineLower := strings.ToLower(line)
	trimmed := strings.TrimSpace(line)
	
	// Skip comments
	if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
	   strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
		return true
	}
	
	// Skip just the word without actual usage
	if issueType == "EVAL" {
		// If it's in a string/comment defining the pattern, not actual eval()
		if strings.Contains(line, "\"EVAL\"") || strings.Contains(line, "'EVAL'") ||
		   strings.Contains(line, "eval\\(") || strings.Contains(line, "eval.*usage") {
			return true
		}
	}
	
	// Shell injection - legitimate monitoring commands
	if issueType == "SHELL_INJECTION" {
		// System monitoring commands in monitoring/security tools are OK
		legitimateCommands := []string{
			"netstat", "ss -", "ps aux", "lsof", "top", "df -h", "free -m",
			"systemctl status", "journalctl", "docker ps", "kubectl get",
		}
		
		for _, cmd := range legitimateCommands {
			if strings.Contains(line, cmd) {
				// Check if it's in a monitoring/agent context
				if strings.Contains(filepath, "agent") || strings.Contains(filepath, "monitor") {
					return true
				}
			}
		}
		
		// Hard-coded safe commands (no user input)
		if strings.Contains(line, "\"sh\", \"-c\"") && 
		   !strings.Contains(lineLower, "input") && 
		   !strings.Contains(lineLower, "user") &&
		   !strings.Contains(line, "+") { // No string concatenation
			return true
		}
	}
	
	// SQL injection - check for parameterized queries
	if issueType == "SQL_INJECTION" {
		// If using prepared statements or parameter binding
		if strings.Contains(lineLower, "prepare") || strings.Contains(line, "?") ||
		   strings.Contains(lineLower, "$1") || strings.Contains(lineLower, "bind") {
			return true
		}
	}
	
	// Hardcoded IP - localhost and common safe IPs
	if issueType == "HARDCODED_IP" {
		safeIPs := []string{"127.0.0.1", "0.0.0.0", "localhost", "192.168."}
		for _, safe := range safeIPs {
			if strings.Contains(line, safe) {
				return true
			}
		}
	}
	
	return false
}

func calculateRiskScore(result *ScanResult) int {
	var score float64 // Use float for precision, convert to int at end

	//  SMART: Weight secrets by confidence score
	for _, secret := range result.Secrets {
		var baseScore float64
		switch secret.Severity {
		case "CRITICAL":
			baseScore = 30
		case "HIGH":
			baseScore = 20
		case "MEDIUM":
			baseScore = 10
		}
		
		// Apply confidence multiplier
		// Low confidence (0.3) = 30% of score
		// High confidence (0.9) = 90% of score
		score += baseScore * secret.Confidence
	}

	// CVEs weighted by CVSS
	for _, cve := range result.CVEs {
		if cve.CVSS >= 9.0 {
			score += 25
		} else if cve.CVSS >= 7.0 {
			score += 15
		} else if cve.CVSS >= 4.0 {
			score += 10
		} else {
			score += 5
		}
	}

	// Code issues (standard scoring)
	for _, issue := range result.CodeIssues {
		switch issue.Severity {
		case "CRITICAL":
			score += 20
		case "HIGH":
			score += 15
		case "MEDIUM":
			score += 8
		case "LOW":
			score += 3
		}
	}

	//  SMART: Bonus/penalty adjustments
	
	// Penalty: Multiple different secret types = likely real leak
	secretTypes := make(map[string]bool)
	for _, s := range result.Secrets {
		secretTypes[s.Type] = true
	}
	if len(secretTypes) >= 3 {
		score += 10 // Diversity penalty
	}
	
	// Bonus: All low-confidence findings = probably safe
	allLowConfidence := true
	for _, s := range result.Secrets {
		if s.Confidence > 0.6 {
			allLowConfidence = false
			break
		}
	}
	if allLowConfidence && len(result.Secrets) > 0 {
		score *= 0.7 // 30% reduction
	}

	finalScore := int(score)
	if finalScore > 100 {
		finalScore = 100
	}

	return finalScore
}

func getRiskLevel(score int) string {
	if score >= 70 {
		return "CRITICAL"
	} else if score >= 50 {
		return "HIGH"
	} else if score >= 30 {
		return "MEDIUM"
	}
	return "LOW"
}

func applyPolicies(result *ScanResult) PolicyResult {
	policy := PolicyResult{
		Passed:     true,
		Violations: []string{},
		Warnings:   []string{},
	}

	// Multi-environment support: Get thresholds from environment
	maxRiskScore := getEnvIntOrDefault("MAX_RISK_SCORE", 70)
	maxRiskProd := getEnvIntOrDefault("MAX_RISK_PROD", 50)
	maxRiskStaging := getEnvIntOrDefault("MAX_RISK_STAGING", 70)
	maxRiskDev := getEnvIntOrDefault("MAX_RISK_DEV", 100)

	// Determine environment from branch or env var
	env := getEnvOrDefault("DEPLOY_ENV", "")
	if env == "" {
		if strings.Contains(result.Branch, "main") || strings.Contains(result.Branch, "master") {
			env = "prod"
		} else if strings.Contains(result.Branch, "staging") {
			env = "staging"
		} else {
			env = "dev"
		}
	}

	var threshold int
	switch env {
	case "prod":
		threshold = maxRiskProd
	case "staging":
		threshold = maxRiskStaging
	default:
		threshold = maxRiskDev
	}

	// Policy 1: Block if risk score exceeds environment threshold
	if result.RiskScore >= threshold {
		policy.Passed = false
		policy.Violations = append(policy.Violations, 
			fmt.Sprintf("Risk score %d exceeds %s threshold of %d", result.RiskScore, env, threshold))
	}

	// Policy 2: Block on critical secrets
	for _, secret := range result.Secrets {
		if secret.Severity == "CRITICAL" {
			policy.Passed = false
			policy.Violations = append(policy.Violations, 
				fmt.Sprintf("Critical secret detected: %s in %s:%d", secret.Type, secret.File, secret.Line))
		}
	}

	// Policy 3: Block on critical CVEs
	for _, cve := range result.CVEs {
		if cve.CVSS >= 9.0 {
			policy.Passed = false
			policy.Violations = append(policy.Violations, 
				fmt.Sprintf("Critical CVE detected: %s (CVSS %.1f) in %s", cve.CVE, cve.CVSS, cve.Package))
		} else if cve.CVSS >= 7.0 {
			policy.Warnings = append(policy.Warnings, 
				fmt.Sprintf("High severity CVE: %s (CVSS %.1f) in %s", cve.CVE, cve.CVSS, cve.Package))
		}
	}

	// Policy 4: Warn on dangerous code patterns
	criticalPatterns := 0
	for _, issue := range result.CodeIssues {
		if issue.Severity == "CRITICAL" {
			criticalPatterns++
		}
	}
	if criticalPatterns >= 3 {
		policy.Warnings = append(policy.Warnings, 
			fmt.Sprintf("%d critical code patterns detected", criticalPatterns))
	}

	return policy
}

// Simple OPA Policy Evaluator (without full OPA dependency)
func evaluateOPAPolicies(result *ScanResult) *PolicyResult {
	policyFile := "policies/security.rego"
	if _, err := os.Stat(policyFile); os.IsNotExist(err) {
		return nil // No policy file, skip
	}

	content, err := os.ReadFile(policyFile)
	if err != nil {
		log.Printf("Warning: Could not read OPA policy file: %v", err)
		return nil
	}

	policy := &PolicyResult{
		Passed:     true,
		Violations: []string{},
		Warnings:   []string{},
	}

	lines := strings.Split(string(content), "\n")
	
	// Simple rule evaluation (basic implementation)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "deny[msg]") {
			// Evaluate deny rules
			if strings.Contains(line, "risk_score") && strings.Contains(line, "70") {
				if result.RiskScore >= 70 {
					policy.Passed = false
					policy.Violations = append(policy.Violations, "OPA Policy: Risk score too high")
				}
			}
			if strings.Contains(line, "EVAL") {
				for _, issue := range result.CodeIssues {
					if issue.Type == "EVAL" {
						policy.Passed = false
						policy.Violations = append(policy.Violations, "OPA Policy: eval() usage forbidden")
					}
				}
			}
			if strings.Contains(line, "SHELL_INJECTION") {
				for _, issue := range result.CodeIssues {
					if issue.Type == "SHELL_INJECTION" {
						policy.Passed = false
						policy.Violations = append(policy.Violations, "OPA Policy: Shell injection detected")
					}
				}
			}
		}
	}

	return policy
}

func generateSummary(result *ScanResult) string {
	return fmt.Sprintf(
		"Scan completed: %d secrets, %d CVEs, %d code issues. Risk level: %s (%d/100). Deployment %s.",
		len(result.Secrets),
		len(result.CVEs),
		len(result.CodeIssues),
		result.RiskLevel,
		result.RiskScore,
		map[bool]string{true: "APPROVED", false: "BLOCKED"}[result.Passed],
	)
}

func handleRiskScore(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Simplified risk calculation endpoint
	result := ScanResult{}
	result.Secrets = scanSecrets(req.RepoPath)
	result.CVEs = scanCVEs(req.RepoPath)
	result.CodeIssues = scanCodePatterns(req.RepoPath)
	result.RiskScore = calculateRiskScore(&result)
	result.RiskLevel = getRiskLevel(result.RiskScore)

	c.JSON(200, gin.H{
		"risk_score": result.RiskScore,
		"risk_level": result.RiskLevel,
	})
}

func handlePolicyValidation(c *gin.Context) {
	var result ScanResult
	if err := c.ShouldBindJSON(&result); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	policyResult := applyPolicies(&result)
	c.JSON(200, policyResult)
}

// Helper functions

func shouldSkipFile(path string) bool {
	skipDirs := []string{".git", "node_modules", "vendor", ".venv", "__pycache__", "dist", "build"}
	skipExts := []string{".jpg", ".png", ".gif", ".pdf", ".zip", ".exe", ".so", ".dylib", ".dll"}

	for _, dir := range skipDirs {
		if strings.Contains(path, dir) {
			return true
		}
	}

	for _, ext := range skipExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}

	return false
}

func relativePath(base, full string) string {
	rel, err := filepath.Rel(base, full)
	if err != nil {
		return full
	}
	return rel
}

func maskSecret(secret string) string {
	if len(secret) <= 8 {
		return "***"
	}
	return secret[:4] + "..." + secret[len(secret)-4:]
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func getSeverityForSecret(secretType string) string {
	criticalTypes := []string{"AWS_KEY", "PRIVATE_KEY", "GITHUB_TOKEN"}
	for _, ct := range criticalTypes {
		if ct == secretType {
			return "CRITICAL"
		}
	}
	return "HIGH"
}

func getSeverityForCodeIssue(issueType string) string {
	critical := []string{"EVAL", "SHELL_INJECTION", "UNSAFE_DESERIALIZATION"}
	high := []string{"EXEC", "SQL_INJECTION"}

	for _, c := range critical {
		if c == issueType {
			return "CRITICAL"
		}
	}
	for _, h := range high {
		if h == issueType {
			return "HIGH"
		}
	}
	return "MEDIUM"
}

func getDescriptionForCodeIssue(issueType string) string {
	descriptions := map[string]string{
		"EVAL":              "Dangerous eval() usage - potential code injection",
		"EXEC":              "Direct command execution - review for injection risks",
		"SHELL_INJECTION":   "Shell command with user input - high injection risk",
		"SQL_INJECTION":     "Potential SQL injection - use parameterized queries",
		"UNSAFE_DESERIALIZATION": "Unsafe deserialization - can lead to RCE",
		"HARDCODED_IP":      "Hardcoded IP address detected",
	}
	return descriptions[issueType]
}

//  SMART: Detect anomalous patterns in findings
func detectAnomalies(findings []SecretFinding) []string {
	var anomalies []string
	
	if len(findings) == 0 {
		return anomalies
	}
	
	// Group by file type
	fileTypes := make(map[string]int)
	severities := make(map[string]int)
	
	for _, f := range findings {
		ext := filepath.Ext(f.File)
		fileTypes[ext]++
		severities[f.Severity]++
	}
	
	total := len(findings)
	
	// Anomaly 1: Secrets concentrated in one file type (>80%)
	for ext, count := range fileTypes {
		if float64(count)/float64(total) > 0.8 {
			anomalies = append(anomalies, fmt.Sprintf("80%%+ secrets in %s files - potential targeted leak", ext))
		}
	}
	
	// Anomaly 2: All high-confidence findings (suspiciously perfect)
	allHighConf := true
	for _, f := range findings {
		if f.Confidence < 0.8 {
			allHighConf = false
			break
		}
	}
	if allHighConf && total > 2 {
		anomalies = append(anomalies, "All findings have high confidence - verify if legitimate")
	}
	
	// Anomaly 3: Unusual severity distribution
	if severities["CRITICAL"] > total/2 {
		anomalies = append(anomalies, "Majority critical secrets - high-risk scenario")
	}
	
	return anomalies
}

//  SMART DETECTION: Context-aware false positive filtering
func isFalsePositive(line, match, patternType, filepath string) bool {
	lineLower := strings.ToLower(line)
	
	// Filter 1: Skip comments
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || 
	   strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
		return true
	}
	
	// Filter 2: Skip variable/constant names (not actual values)
	if patternType == "PASSWORD" {
		// If it's just the word "password" in a variable name, not a value
		if strings.Contains(lineLower, "password") && !strings.Contains(line, "=") {
			return true
		}
		// Common false positives
		if strings.Contains(lineLower, "const") || strings.Contains(lineLower, "var") ||
		   strings.Contains(lineLower, "password_") || strings.Contains(lineLower, "passwordfield") {
			return true
		}
	}
	
	// Filter 3: Skip test files and examples
	if strings.Contains(filepath, "_test.go") || strings.Contains(filepath, "test_") ||
	   strings.Contains(filepath, "example") || strings.Contains(filepath, "mock") {
		// Still catch CRITICAL secrets even in tests
		if patternType != "AWS_KEY" && patternType != "GITHUB_TOKEN" && patternType != "PRIVATE_KEY" {
			return true
		}
	}
	
	// Filter 4: Skip documentation
	if strings.HasSuffix(filepath, ".md") || strings.HasSuffix(filepath, ".txt") {
		return true
	}
	
	// Filter 5: Skip placeholder/example values
	placeholders := []string{"example", "sample", "test", "dummy", "fake", "placeholder", "your_", "xxx"}
	matchLower := strings.ToLower(match)
	for _, ph := range placeholders {
		if strings.Contains(matchLower, ph) {
			return true
		}
	}
	
	return false
}

// 🧠 CONFIDENCE SCORING: Calculate how likely this is a real secret
func calculateConfidence(line, match, patternType string) float64 {
	confidence := 0.5 // Start at 50%
	
	lineLower := strings.ToLower(line)
	
	// Boost confidence factors
	if strings.Contains(lineLower, "secret") || strings.Contains(lineLower, "key") ||
	   strings.Contains(lineLower, "token") || strings.Contains(lineLower, "password") {
		confidence += 0.2
	}
	
	if strings.Contains(line, "=") && strings.Contains(line, "\"") {
		confidence += 0.15 // Looks like an assignment
	}
	
	if patternType == "AWS_KEY" || patternType == "GITHUB_TOKEN" || patternType == "PRIVATE_KEY" {
		confidence += 0.2 // These patterns are very specific
	}
	
	// Reduce confidence factors
	if strings.Contains(lineLower, "example") || strings.Contains(lineLower, "test") {
		confidence -= 0.3
	}
	
	if strings.Contains(lineLower, "//") || strings.Contains(lineLower, "#") {
		confidence -= 0.2 // In comment
	}
	
	// Entropy check - real secrets have high randomness
	entropy := calculateEntropy(match)
	if entropy > 3.5 {
		confidence += 0.15
	} else if entropy < 2.0 {
		confidence -= 0.2
	}
	
	// Clamp between 0 and 1
	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0.0 {
		confidence = 0.0
	}
	
	return confidence
}

// Calculate Shannon entropy (randomness measure)
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	
	freq := make(map[rune]float64)
	for _, char := range s {
		freq[char]++
	}
	
	var entropy float64
	length := float64(len(s))
	
	for _, count := range freq {
		probability := count / length
		entropy -= probability * (math.Log2(probability))
	}
	
	return entropy
}

// Helper functions for environment variables
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}