use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use rayon::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub file: String,
    pub line: usize,
    pub secret_type: String,
    pub severity: String,
    pub matched_text: String,
    pub confidence: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub secrets: Vec<SecretFinding>,
}

pub struct SecretScanner {
    patterns: HashMap<String, Regex>,
}

impl SecretScanner {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();

        // AWS patterns
        patterns.insert("AWS_KEY".to_string(), Regex::new(r"AKIA[0-9A-Z]{16}").unwrap());
        patterns.insert("AWS_SECRET".to_string(), Regex::new(r"(?i)aws[_-]?secret[_-]?access[_-]?key["\s:=]+[A-Za-z0-9/+=]{40}").unwrap());

        // Git tokens
        patterns.insert("GITHUB_TOKEN".to_string(), Regex::new(r"gh[pousr]_[A-Za-z0-9]{36,}").unwrap());
        patterns.insert("GITLAB_TOKEN".to_string(), Regex::new(r"glpat-[A-Za-z0-9_-]{20,}").unwrap());

        // JWT patterns
        patterns.insert("JWT_TOKEN".to_string(), Regex::new(r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*").unwrap());
        patterns.insert("BEARER_TOKEN".to_string(), Regex::new(r"(?i)bearer\s+[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]*").unwrap());

        // API Keys
        patterns.insert("STRIPE_KEY".to_string(), Regex::new(r"sk_(?:live|test)_[A-Za-z0-9]{24,}").unwrap());
        patterns.insert("TWILIO_KEY".to_string(), Regex::new(r"SK[A-Za-z0-9]{32}").unwrap());
        patterns.insert("SENDGRID_KEY".to_string(), Regex::new(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}").unwrap());
        patterns.insert("MAILGUN_KEY".to_string(), Regex::new(r"key-[A-Za-z0-9]{32}").unwrap());
        patterns.insert("GOOGLE_API_KEY".to_string(), Regex::new(r"AIza[0-9A-Za-z-_]{35}").unwrap());
        patterns.insert("AZURE_KEY".to_string(), Regex::new(r"(?i)azure[_-]?key["\s:=]+[A-Za-z0-9+/=]{44}").unwrap());

        // Other patterns
        patterns.insert("SLACK_TOKEN".to_string(), Regex::new(r"xox[baprs]-[0-9a-zA-Z]{10,48}").unwrap());
        patterns.insert("DISCORD_TOKEN".to_string(), Regex::new(r"[MN][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{27,}").unwrap());
        patterns.insert("PRIVATE_KEY".to_string(), Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap());
        patterns.insert("GENERIC_API_KEY".to_string(), Regex::new(r"(?i)api[_-]?key["\s:=]+[a-z0-9]{20,}").unwrap());
        patterns.insert("PASSWORD".to_string(), Regex::new(r"(?i)password["\s:=]+[^"\s]{8,}").unwrap());
        patterns.insert("DATABASE_URL".to_string(), Regex::new(r"(?i)(postgres|mysql|mongodb)://[^\s"']+").unwrap());

        SecretScanner { patterns }
    }

    pub fn scan_directory(&self, dir_path: &str) -> Result<ScanResult, Box<dyn std::error::Error>> {
        let mut all_findings = Vec::new();
        let mut seen_hashes = HashMap::new();

        // Collect all files to scan
        let files: Vec<_> = self.collect_files(dir_path)?;

        // Process files in parallel
        let findings: Vec<Vec<SecretFinding>> = files.par_iter()
            .map(|file_path| {
                self.scan_file(file_path, dir_path, &mut seen_hashes.clone())
            })
            .collect();

        // Flatten results
        for mut file_findings in findings {
            all_findings.append(&mut file_findings);
        }

        Ok(ScanResult { secrets: all_findings })
    }

    fn collect_files(&self, dir_path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut files = Vec::new();
        self.collect_files_recursive(dir_path, &mut files)?;
        Ok(files)
    }

    fn collect_files_recursive(&self, dir_path: &str, files: &mut Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
        let entries = fs::read_dir(dir_path)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                // Skip common directories
                let dir_name = path.file_name().unwrap().to_str().unwrap();
                if !self.should_skip_directory(dir_name) {
                    self.collect_files_recursive(path.to_str().unwrap(), files)?;
                }
            } else if path.is_file() {
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if !self.should_skip_file(file_name) {
                        files.push(path.to_str().unwrap().to_string());
                    }
                }
            }
        }

        Ok(())
    }

    fn should_skip_directory(&self, dir_name: &str) -> bool {
        matches!(dir_name, ".git" | "node_modules" | "target" | ".cargo" | "__pycache__" | "build" | "dist")
    }

    fn should_skip_file(&self, file_name: &str) -> bool {
        // Skip binary files and common non-text files
        let skip_extensions = ["jpg", "jpeg", "png", "gif", "bmp", "ico", "pdf", "zip", "tar", "gz", "exe", "dll", "so", "dylib"];
        if let Some(ext) = Path::new(file_name).extension().and_then(|e| e.to_str()) {
            return skip_extensions.contains(&ext);
        }
        false
    }

    fn scan_file(&self, file_path: &str, base_path: &str, seen_hashes: &mut HashMap<String, bool>) -> Vec<SecretFinding> {
        let mut findings = Vec::new();

        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => return findings, // Skip files we can't read
        };

        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for (pattern_type, regex) in &self.patterns {
                if let Some(mat) = regex.find(line) {
                    let matched_text = mat.as_str();

                    // Check for false positives
                    if self.is_false_positive(line, pattern_type) {
                        continue;
                    }

                    // Deduplication
                    let hash = self.hash_string(matched_text);
                    if seen_hashes.contains_key(&hash) {
                        continue;
                    }
                    seen_hashes.insert(hash, true);

                    let confidence = self.calculate_confidence(line, matched_text, pattern_type);
                    let severity = self.get_severity_for_secret(pattern_type);
                    let masked_match = self.mask_secret(matched_text);

                    let relative_path = self.relative_path(base_path, file_path);

                    findings.push(SecretFinding {
                        file: relative_path,
                        line: line_num + 1,
                        secret_type: pattern_type.clone(),
                        severity,
                        matched_text: masked_match,
                        confidence,
                    });
                }
            }
        }

        findings
    }

    fn is_false_positive(&self, line: &str, pattern_type: &str) -> bool {
        let line_lower = line.to_lowercase();

        // Common false positive contexts
        let false_positive_contexts = ["readme", "documentation", "example", "sample", "test", "demo", "placeholder", "your_", "replace_with", "fake", "mock"];

        for ctx in &false_positive_contexts {
            if line_lower.contains(ctx) {
                return true;
            }
        }

        // Specific checks
        match pattern_type {
            "JWT_TOKEN" | "BEARER_TOKEN" => {
                line_lower.contains("example") || line_lower.contains("test")
            }
            "GOOGLE_API_KEY" => {
                line_lower.contains("console.developers.google.com")
            }
            _ => false,
        }
    }

    fn calculate_confidence(&self, line: &str, matched_text: &str, pattern_type: &str) -> f64 {
        let mut confidence = 0.5;

        let line_lower = line.to_lowercase();

        // Boost confidence factors
        if line_lower.contains("secret") || line_lower.contains("key") ||
           line_lower.contains("token") || line_lower.contains("password") ||
           line_lower.contains("auth") || line_lower.contains("bearer") {
            confidence += 0.2;
        }

        if line.contains('=') && (line.contains('"') || line.contains('\'')) {
            confidence += 0.15;
        }

        // High-confidence patterns
        let high_confidence = ["AWS_KEY", "AWS_SECRET", "GITHUB_TOKEN", "GITLAB_TOKEN", "PRIVATE_KEY", "STRIPE_KEY", "TWILIO_KEY", "SENDGRID_KEY", "SLACK_TOKEN", "DISCORD_TOKEN", "GOOGLE_API_KEY"];
        if high_confidence.contains(&pattern_type) {
            confidence += 0.25;
        }

        // Medium-confidence patterns
        let medium_confidence = ["JWT_TOKEN", "BEARER_TOKEN", "AZURE_KEY", "MAILGUN_KEY"];
        if medium_confidence.contains(&pattern_type) {
            confidence += 0.15;
        }

        // Reduce confidence for false positives
        if self.is_false_positive(line, pattern_type) {
            confidence -= 0.4;
        }

        // Entropy check
        let entropy = self.calculate_entropy(matched_text);
        if entropy > 4.0 {
            confidence += 0.2;
        } else if entropy > 3.0 {
            confidence += 0.1;
        } else if entropy < 2.0 {
            confidence -= 0.2;
        }

        // Length check
        if matched_text.len() < 10 {
            confidence -= 0.1;
        } else if matched_text.len() > 50 {
            confidence += 0.1;
        }

        confidence.max(0.0).min(1.0)
    }

    fn calculate_entropy(&self, s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut freq = HashMap::new();
        for ch in s.chars() {
            *freq.entry(ch).or_insert(0) += 1;
        }

        let length = s.len() as f64;
        let mut entropy = 0.0;

        for &count in freq.values() {
            let probability = count as f64 / length;
            entropy -= probability * probability.log2();
        }

        entropy
    }

    fn get_severity_for_secret(&self, pattern_type: &str) -> String {
        match pattern_type {
            "AWS_KEY" | "AWS_SECRET" | "PRIVATE_KEY" | "STRIPE_KEY" => "CRITICAL",
            "GITHUB_TOKEN" | "GITLAB_TOKEN" | "SLACK_TOKEN" | "DISCORD_TOKEN" => "HIGH",
            "JWT_TOKEN" | "BEARER_TOKEN" | "GOOGLE_API_KEY" | "AZURE_KEY" => "MEDIUM",
            _ => "LOW",
        }.to_string()
    }

    fn mask_secret(&self, secret: &str) -> String {
        if secret.len() <= 8 {
            return "*".repeat(secret.len());
        }

        let visible_start = 4;
        let visible_end = 4;
        let mask_len = secret.len().saturating_sub(visible_start + visible_end);

        format!("{}{}{}",
                &secret[..visible_start.min(secret.len())],
                "*".repeat(mask_len),
                &secret[secret.len().saturating_sub(visible_end)..])
    }

    fn hash_string(&self, s: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        hasher.finish().to_string()
    }

    fn relative_path(&self, base: &str, full: &str) -> String {
        Path::new(full).strip_prefix(base).unwrap_or(Path::new(full)).to_string_lossy().to_string()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <directory>", args[0]);
        std::process::exit(1);
    }

    let scanner = SecretScanner::new();
    let result = scanner.scan_directory(&args[1])?;

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_entropy() {
        let scanner = SecretScanner::new();
        assert!(scanner.calculate_entropy("sk_test_1234567890123456789012345678901234567890") > 4.0);
        assert!(scanner.calculate_entropy("aaaaaaaa") < 1.0);
    }

    #[test]
    fn test_mask_secret() {
        let scanner = SecretScanner::new();
        assert_eq!(scanner.mask_secret("short"), "*****");
        assert_eq!(scanner.mask_secret("verylongsecretkey123456789"), "very*************************6789");
    }

    #[test]
    fn test_is_false_positive() {
        let scanner = SecretScanner::new();
        assert!(scanner.is_false_positive("// Example JWT token", "JWT_TOKEN"));
        assert!(!scanner.is_false_positive("api_key = \"sk_test_123\"", "STRIPE_KEY"));
    }
}