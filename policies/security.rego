# OPA Policy Examples for Guardian-Ops

# These policies can be integrated with the Security API for advanced rule enforcement

package devsecops.policies

# Default deny
default allow = false

# Policy 1: Block deployments with critical vulnerabilities
allow {
    input.risk_score < 70
    count(critical_secrets) == 0
    count(critical_cves) == 0
}

# Policy 2: Allow with warnings for medium risk
allow {
    input.risk_score >= 30
    input.risk_score < 70
    count(critical_secrets) == 0
    has_approval
}

# Helper: Find critical secrets
critical_secrets[secret] {
    secret := input.secrets[_]
    secret.severity == "CRITICAL"
}

# Helper: Find critical CVEs
critical_cves[cve] {
    cve := input.cves[_]
    cve.cvss >= 9.0
}

# Helper: Check if deployment has approval
has_approval {
    input.approved_by != ""
}

# Policy 3: Deny if specific patterns detected
deny[msg] {
    input.code_issues[_].type == "EVAL"
    msg := "eval() usage is forbidden in production code"
}

deny[msg] {
    input.code_issues[_].type == "SHELL_INJECTION"
    msg := "Shell injection vulnerability detected - deployment blocked"
}

# Policy 4: Require all dependencies to be scanned
deny[msg] {
    not has_dependency_scan
    msg := "All dependencies must be scanned for CVEs"
}

has_dependency_scan {
    count(input.cves) >= 0
}

# Policy 5: Block deployments outside business hours (optional)
deny[msg] {
    is_production_deployment
    not is_business_hours
    not has_emergency_approval
    msg := "Production deployments outside business hours require emergency approval"
}

is_production_deployment {
    input.branch == "main"
}

is_business_hours {
    # Simplified: In real implementation, check actual time
    true
}

has_emergency_approval {
    input.emergency_approved == true
}

# Policy 6: Risk score thresholds by environment
max_risk_score[score] {
    input.environment == "production"
    score := 50
}

max_risk_score[score] {
    input.environment == "staging"
    score := 70
}

max_risk_score[score] {
    input.environment == "development"
    score := 100
}

# Policy 7: Require specific scanners to pass
required_scanners := ["secrets", "cve", "code_analysis"]

deny[msg] {
    scanner := required_scanners[_]
    not scanner_passed(scanner)
    msg := sprintf("Required scanner '%s' did not pass", [scanner])
}

scanner_passed(scanner) {
    input.scanners[scanner].status == "passed"
}
