use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use regex::Regex;
use tree_sitter::{Parser, Language};
use rayon::prelude::*;
use tree_sitter_rust::LANGUAGE as rust_language;
use tree_sitter_javascript::LANGUAGE as js_language;
use tree_sitter_python::LANGUAGE as python_language;
use tree_sitter_go::LANGUAGE as go_language;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFinding {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub finding_type: String,
    pub severity: String,
    pub description: String,
    pub confidence: f64,
    pub code_context: String,
    pub vulnerability_class: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdvancedScanResult {
    pub findings: Vec<AdvancedFinding>,
    pub language_stats: HashMap<String, usize>,
    pub performance_metrics: PerformanceMetrics,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub files_processed: usize,
    pub total_lines: usize,
    pub analysis_time_ms: u64,
    pub memory_peak_mb: usize,
}

pub struct AdvancedSecurityAnalyzer {
    parsers: HashMap<String, Parser>,
    patterns: HashMap<String, Regex>,
}

impl AdvancedSecurityAnalyzer {
    pub fn new() -> Self {
        let mut parsers = HashMap::new();

        // Initialize parsers for different languages
        parsers.insert("rs".to_string(), Self::create_parser(rust_language()));
        parsers.insert("js".to_string(), Self::create_parser(js_language()));
        parsers.insert("ts".to_string(), Self::create_parser(js_language()));
        parsers.insert("py".to_string(), Self::create_parser(python_language()));
        parsers.insert("go".to_string(), Self::create_parser(go_language()));

        let patterns = Self::load_advanced_patterns();

        AdvancedSecurityAnalyzer { parsers, patterns }
    }

    fn create_parser(language: Language) -> Parser {
        let mut parser = Parser::new();
        parser.set_language(&language).unwrap();
        parser
    }

    fn load_advanced_patterns() -> HashMap<String, Regex> {
        let mut patterns = HashMap::new();

        // Advanced patterns that go beyond simple regex
        patterns.insert("dangerous_eval".to_string(),
            Regex::new(r"(?i)(eval|exec|Function|setTimeout|setInterval)\s*\(\s*.*\+.*\)").unwrap());
        patterns.insert("unsafe_deserialization".to_string(),
            Regex::new(r"(?i)(pickle\.loads|yaml\.load|Marshal\.load|JSON\.parse\s*\(\s*.*\))").unwrap());
        patterns.insert("sql_injection_advanced".to_string(),
            Regex::new(r"execute\s*\(\s*.*\$[0-9]+.*\)|query\s*\(\s*.*\{.*\}.*\)").unwrap());
        patterns.insert("xss_vector".to_string(),
            Regex::new(r"innerHTML\s*=\s*.*\+.*|document\.write\s*\(\s*.*\+.*\)").unwrap());
        patterns.insert("path_traversal".to_string(),
            Regex::new(r"\.\./|\.\.\\|~|%2e%2e").unwrap());
        patterns.insert("command_injection".to_string(),
            Regex::new(r"(?i)(exec|system|popen|spawn)\s*\(\s*.*\$[a-zA-Z_][a-zA-Z0-9_]*.*\)").unwrap());

        patterns
    }

    pub fn analyze_file(&mut self, file_path: &str, content: &str) -> Vec<AdvancedFinding> {
        let mut findings = Vec::new();

        let extension = std::path::Path::new(file_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        // 1. AST-based analysis for supported languages
        if self.parsers.contains_key(extension) {
            // Separate mutable borrow scope to avoid holding it during method call
            let ast_findings = {
                let parser = self.parsers.get_mut(extension).unwrap();
                Self::ast_analysis(parser, file_path, content, extension)
            };
            findings.extend(ast_findings);
        }

        // 2. Advanced regex patterns
        findings.extend(self.pattern_analysis(file_path, content));

        // 3. Data flow analysis (simplified)
        findings.extend(self.data_flow_analysis(file_path, content));

        // 4. Cryptographic analysis
        findings.extend(self.crypto_analysis(file_path, content));

        findings
    }

    fn ast_analysis(parser: &mut Parser, file_path: &str, content: &str, lang: &str) -> Vec<AdvancedFinding> {
        let mut findings = Vec::new();

        let tree = match parser.parse(content, None) {
            Some(t) => t,
            None => return findings,
        };

        let root_node = tree.root_node();

        match lang {
            "rs" => findings.extend(Self::analyze_rust_ast(&root_node, content, file_path)),
            "js" | "ts" => findings.extend(Self::analyze_js_ast(&root_node, content, file_path)),
            "py" => findings.extend(Self::analyze_python_ast(&root_node, content, file_path)),
            "go" => findings.extend(Self::analyze_go_ast(&root_node, content, file_path)),
            _ => {}
        }

        findings
    }

    fn analyze_rust_ast(node: &tree_sitter::Node, source: &str, file_path: &str) -> Vec<AdvancedFinding> {
        let mut findings = Vec::new();

        // Walk the AST looking for security issues
        let mut cursor = node.walk();

        loop {
            let current_node = cursor.node();

            // Check for unsafe blocks
            if current_node.kind() == "unsafe_block" {
                findings.push(AdvancedFinding {
                    file: file_path.to_string(),
                    line: current_node.start_position().row + 1,
                    column: current_node.start_position().column + 1,
                    finding_type: "unsafe_block".to_string(),
                    severity: "MEDIUM".to_string(),
                    description: "Unsafe block allows raw pointer operations".to_string(),
                    confidence: 0.9,
                    code_context: Self::extract_context(source, &current_node),
                    vulnerability_class: "Memory Safety".to_string(),
                });
            }

            // Check for unwrap() calls (potential panics)
            if current_node.kind() == "call_expression" {
                let call_text = current_node.utf8_text(source.as_bytes()).unwrap_or("");
                if call_text.contains("unwrap()") || call_text.contains("expect(") {
                    findings.push(AdvancedFinding {
                        file: file_path.to_string(),
                        line: current_node.start_position().row + 1,
                        column: current_node.start_position().column + 1,
                        finding_type: "unwrap_usage".to_string(),
                        severity: "LOW".to_string(),
                        description: "Use of unwrap() or expect() may cause panics".to_string(),
                        confidence: 0.7,
                        code_context: Self::extract_context(source, &current_node),
                        vulnerability_class: "Error Handling".to_string(),
                    });
                }
            }

            if !cursor.goto_first_child() {
                if !cursor.goto_next_sibling() {
                    loop {
                        cursor.goto_parent();
                        if !cursor.goto_next_sibling() {
                            if cursor.node() == *node {
                                return findings;
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }

    fn analyze_js_ast(node: &tree_sitter::Node, source: &str, file_path: &str) -> Vec<AdvancedFinding> {
        let mut findings = Vec::new();
        let mut cursor = node.walk();

        loop {
            let current_node = cursor.node();

            // Check for eval usage
            if current_node.kind() == "call_expression" {
                let call_text = current_node.utf8_text(source.as_bytes()).unwrap_or("");
                if call_text.starts_with("eval(") {
                    findings.push(AdvancedFinding {
                        file: file_path.to_string(),
                        line: current_node.start_position().row + 1,
                        column: current_node.start_position().column + 1,
                        finding_type: "eval_usage".to_string(),
                        severity: "HIGH".to_string(),
                        description: "Use of eval() can execute arbitrary code".to_string(),
                        confidence: 0.95,
                        code_context: Self::extract_context(source, &current_node),
                        vulnerability_class: "Code Injection".to_string(),
                    });
                }
            }

            // Check for innerHTML assignments
            if current_node.kind() == "assignment_expression" {
                let assign_text = current_node.utf8_text(source.as_bytes()).unwrap_or("");
                if assign_text.contains("innerHTML") && assign_text.contains("+") {
                    findings.push(AdvancedFinding {
                        file: file_path.to_string(),
                        line: current_node.start_position().row + 1,
                        column: current_node.start_position().column + 1,
                        finding_type: "xss_innerhtml".to_string(),
                        severity: "HIGH".to_string(),
                        description: "Potential XSS via innerHTML with string concatenation".to_string(),
                        confidence: 0.85,
                        code_context: Self::extract_context(source, &current_node),
                        vulnerability_class: "Cross-Site Scripting".to_string(),
                    });
                }
            }

            if !cursor.goto_first_child() {
                if !cursor.goto_next_sibling() {
                    loop {
                        cursor.goto_parent();
                        if !cursor.goto_next_sibling() {
                            if cursor.node() == *node {
                                return findings;
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }

    fn analyze_python_ast(node: &tree_sitter::Node, source: &str, file_path: &str) -> Vec<AdvancedFinding> {
        let mut findings = Vec::new();
        let mut cursor = node.walk();

        loop {
            let current_node = cursor.node();

            // Check for exec/eval usage
            if current_node.kind() == "call" {
                let call_text = current_node.utf8_text(source.as_bytes()).unwrap_or("");
                if call_text.starts_with("exec(") || call_text.starts_with("eval(") {
                    findings.push(AdvancedFinding {
                        file: file_path.to_string(),
                        line: current_node.start_position().row + 1,
                        column: current_node.start_position().column + 1,
                        finding_type: "dynamic_execution".to_string(),
                        severity: "CRITICAL".to_string(),
                        description: "Use of exec() or eval() allows code execution".to_string(),
                        confidence: 0.95,
                        code_context: Self::extract_context(source, &current_node),
                        vulnerability_class: "Code Injection".to_string(),
                    });
                }
            }

            if !cursor.goto_first_child() {
                if !cursor.goto_next_sibling() {
                    loop {
                        cursor.goto_parent();
                        if !cursor.goto_next_sibling() {
                            if cursor.node() == *node {
                                return findings;
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }

    fn analyze_go_ast(node: &tree_sitter::Node, source: &str, file_path: &str) -> Vec<AdvancedFinding> {
        let mut findings = Vec::new();
        let mut cursor = node.walk();

        loop {
            let current_node = cursor.node();

            // Check for SQL injection patterns
            if current_node.kind() == "call_expression" {
                let call_text = current_node.utf8_text(source.as_bytes()).unwrap_or("");
                if call_text.contains("Query(") || call_text.contains("Exec(") {
                    // Check if using string concatenation
                    if call_text.contains(" + ") || call_text.contains(" fmt.Sprintf") {
                        findings.push(AdvancedFinding {
                            file: file_path.to_string(),
                            line: current_node.start_position().row + 1,
                            column: current_node.start_position().column + 1,
                            finding_type: "sql_injection".to_string(),
                            severity: "HIGH".to_string(),
                            description: "Potential SQL injection via string concatenation".to_string(),
                            confidence: 0.8,
                            code_context: Self::extract_context(source, &current_node),
                            vulnerability_class: "SQL Injection".to_string(),
                        });
                    }
                }
            }

            if !cursor.goto_first_child() {
                if !cursor.goto_next_sibling() {
                    loop {
                        cursor.goto_parent();
                        if !cursor.goto_next_sibling() {
                            if cursor.node() == *node {
                                return findings;
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }

    fn pattern_analysis(&self, file_path: &str, content: &str) -> Vec<AdvancedFinding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for (pattern_name, regex) in &self.patterns {
                if let Some(mat) = regex.find(line) {
                    let severity = match pattern_name.as_str() {
                        "dangerous_eval" | "command_injection" => "CRITICAL",
                        "unsafe_deserialization" | "sql_injection_advanced" => "HIGH",
                        "xss_vector" => "HIGH",
                        "path_traversal" => "MEDIUM",
                        _ => "LOW",
                    };

                    findings.push(AdvancedFinding {
                        file: file_path.to_string(),
                        line: line_num + 1,
                        column: mat.start(),
                        finding_type: pattern_name.clone(),
                        severity: severity.to_string(),
                        description: self.get_pattern_description(pattern_name),
                        confidence: 0.8,
                        code_context: line.trim().to_string(),
                        vulnerability_class: self.get_vulnerability_class(pattern_name),
                    });
                }
            }
        }

        findings
    }

    fn data_flow_analysis(&self, file_path: &str, content: &str) -> Vec<AdvancedFinding> {
        let mut findings = Vec::new();

        // Simple data flow: look for user input flowing to dangerous sinks
        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            // Look for patterns like: dangerous_function(user_input)
            if line.contains("eval(") || line.contains("exec(") || line.contains("system(") {
                if line.contains("req.") || line.contains("request.") || line.contains("input") {
                    findings.push(AdvancedFinding {
                        file: file_path.to_string(),
                        line: line_num + 1,
                        column: 0,
                        finding_type: "tainted_data_flow".to_string(),
                        severity: "CRITICAL".to_string(),
                        description: "User input flows to dangerous function".to_string(),
                        confidence: 0.9,
                        code_context: line.trim().to_string(),
                        vulnerability_class: "Injection".to_string(),
                    });
                }
            }
        }

        findings
    }

    fn crypto_analysis(&self, file_path: &str, content: &str) -> Vec<AdvancedFinding> {
        let mut findings = Vec::new();

        // Check for weak cryptographic practices
        let weak_crypto_patterns = vec![
            r"MD5|md5",
            r"SHA1|sha1",
            r"DES|des",
            r"RC4|rc4",
        ];

        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &weak_crypto_patterns {
                if let Ok(regex) = Regex::new(pattern) {
                    if regex.is_match(line) {
                        findings.push(AdvancedFinding {
                            file: file_path.to_string(),
                            line: line_num + 1,
                            column: 0,
                            finding_type: "weak_crypto".to_string(),
                            severity: "MEDIUM".to_string(),
                            description: format!("Use of weak cryptographic algorithm: {}", pattern),
                            confidence: 0.7,
                            code_context: line.trim().to_string(),
                            vulnerability_class: "Cryptography".to_string(),
                        });
                    }
                }
            }
        }

        findings
    }

    fn extract_context(source: &str, node: &tree_sitter::Node) -> String {
        let start = node.start_byte();
        let end = node.end_byte();
        let context_start = start.saturating_sub(50);
        let context_end = (end + 50).min(source.len());

        source[context_start..context_end].to_string()
    }

    fn get_pattern_description(&self, pattern: &str) -> String {
        match pattern {
            "dangerous_eval" => "Dangerous use of eval/exec with dynamic content".to_string(),
            "unsafe_deserialization" => "Unsafe deserialization of untrusted data".to_string(),
            "sql_injection_advanced" => "Potential SQL injection via parameterized queries".to_string(),
            "xss_vector" => "Potential XSS via DOM manipulation".to_string(),
            "path_traversal" => "Path traversal vulnerability".to_string(),
            "command_injection" => "Command injection vulnerability".to_string(),
            _ => "Security vulnerability detected".to_string(),
        }
    }

    fn get_vulnerability_class(&self, pattern: &str) -> String {
        match pattern {
            "dangerous_eval" | "command_injection" => "Code Injection".to_string(),
            "unsafe_deserialization" => "Deserialization".to_string(),
            "sql_injection_advanced" => "SQL Injection".to_string(),
            "xss_vector" => "Cross-Site Scripting".to_string(),
            "path_traversal" => "Directory Traversal".to_string(),
            _ => "General".to_string(),
        }
    }
}

// FFI Interface for Go integration
#[no_mangle]
pub extern "C" fn analyze_file_ffi(
    file_path: *const c_char,
    content: *const c_char,
) -> *mut c_char {
    let file_path_str = unsafe { CStr::from_ptr(file_path).to_str().unwrap_or("") };
    let content_str = unsafe { CStr::from_ptr(content).to_str().unwrap_or("") };

    let mut analyzer = AdvancedSecurityAnalyzer::new();
    let findings = analyzer.analyze_file(file_path_str, content_str);

    let result = AdvancedScanResult {
        findings,
        language_stats: HashMap::new(),
        performance_metrics: PerformanceMetrics {
            files_processed: 1,
            total_lines: content_str.lines().count(),
            analysis_time_ms: 0, // Would need timing
            memory_peak_mb: 0,   // Would need memory tracking
        },
    };

    let json = serde_json::to_string(&result).unwrap_or("{}".to_string());
    let c_string = CString::new(json).unwrap();
    c_string.into_raw()
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    unsafe {
        if !s.is_null() {
            drop(CString::from_raw(s));
        }
    }
}

// Async analysis function for high-throughput processing
pub async fn analyze_repository_async(repo_path: &str) -> Result<AdvancedScanResult, anyhow::Error> {
    let start_time = std::time::Instant::now();

    // Collect all source files
    let files = AdvancedSecurityAnalyzer::collect_source_files(repo_path)?;

    // Analyze files in parallel
    let findings: Vec<AdvancedFinding> = files
        .into_par_iter()
        .flat_map(|file_path| {
            std::fs::read_to_string(&file_path)
                .ok()
                .map(|content| {
                    let mut file_analyzer = AdvancedSecurityAnalyzer::new();
                    file_analyzer.analyze_file(&file_path, &content)
                })
                .unwrap_or_default()
        })
        .collect();

    let analysis_time = start_time.elapsed().as_millis() as u64;
    
    // Capture findings length before moving
    let findings_count = findings.len();

    Ok(AdvancedScanResult {
        findings,
        language_stats: HashMap::new(), // Would compute from files
        performance_metrics: PerformanceMetrics {
            files_processed: findings_count,
            total_lines: 0, // Would compute
            analysis_time_ms: analysis_time,
            memory_peak_mb: 0, // Would track
        },
    })
}

impl AdvancedSecurityAnalyzer {
    fn collect_source_files(repo_path: &str) -> Result<Vec<String>, anyhow::Error> {
        let mut files = Vec::new();
        Self::collect_files_recursive(repo_path, &mut files)?;
        Ok(files)
    }

    fn collect_files_recursive(dir_path: &str, files: &mut Vec<String>) -> Result<(), anyhow::Error> {
        for entry in std::fs::read_dir(dir_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                let dir_name = path.file_name().unwrap().to_str().unwrap();
                if !matches!(dir_name, ".git" | "node_modules" | "target" | "__pycache__" | ".cargo") {
                    Self::collect_files_recursive(path.to_str().unwrap(), files)?;
                }
            } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if matches!(ext, "rs" | "js" | "ts" | "py" | "go" | "java") {
                    files.push(path.to_str().unwrap().to_string());
                }
            }
        }
        Ok(())
    }
}