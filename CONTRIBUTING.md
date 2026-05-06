# Contributing to Guardian-Ops

Thank you for your interest in contributing! This project aims to make DevSecOps accessible and production-ready.

##  Getting Started

1. **Fork the repository**
2. **Clone your fork**
   ```bash
   git clone https://github.com/Yousef-G0/guardian-ops.git
   cd guardian-ops
   ```

3. **Create a branch**
   ```bash
   git checkout -b feature/feature-name
   ```

##  Development Setup

```bash
# Run setup script
./setup.sh

# Build and test
cd cmd/api
go build -o ../../bin/security-api main.go
cd ../..

# Run tests
./bin/security-api &
sleep 3
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "."}' | jq '.'
```

##  Contribution Guidelines

### Code Quality

- Write clean, readable Go code
- Follow Go best practices and idioms
- Add comments for complex logic
- Keep functions focused and small

### Testing

- Test your changes thoroughly
- Add test cases for new features
- Ensure existing tests still pass
- Document test scenarios

### Security

- Never commit real secrets or credentials
- Use placeholder values in examples
- Review security implications of changes
- Follow secure coding practices

### Documentation

- Update README.md if adding features
- Add code comments where necessary
- Document API changes
- Include examples for new functionality

##  Pull Request Process

1. **Update documentation**
   - README.md for user-facing changes
   - Code comments for implementation details

2. **Test thoroughly**
   - Build and test the API locally
   - Run security scans on test repositories
   - Test manually if needed
   - Verify no regressions

3. **Write a clear PR description**
   - What does this change?
   - Why is it needed?
   - How was it tested?

4. **Follow commit conventions**
   ```
   feat: Add new security pattern detection
   fix: Correct risk score calculation
   docs: Update API reference
   test: Add CVE scanner tests
   ```

5. **Wait for review**
   - Address feedback promptly
   - Be open to suggestions
   - Iterate as needed


## Future Enhancements

1. **Machine Learning**
   - Behavioral anomaly detection
   - Risk score optimization
   - False positive reduction

2. **Multi-Cloud Support**
   - AWS, GCP, Azure integrations
   - Cloud-native monitoring

3. **Advanced Policies**
   - Time-based rules
   - User-based approvals
   - Multi-factor verification

4. **Dashboard**
   - Real-time monitoring UI
   - Historical trend analysis
   - Security metrics visualization

5. **Integrations**
   - Slack, PagerDuty, Datadog
   - SIEM systems
   - Ticket systems (Jira, Linear)

##  Areas for Contribution

### High Priority

- [ ] Additional secret patterns
- [ ] More CVE data sources
- [ ] Enhanced anomaly detection
- [ ] Performance optimizations
- [ ] Better error handling

### Medium Priority

- [ ] Web dashboard
- [ ] Additional deployment targets
- [ ] More notification channels
- [ ] Extended OPA policies
- [ ] CLI tools

### Low Priority

- [ ] Additional language support
- [ ] Custom report formats
- [ ] Integration with other tools
- [ ] Visualization improvements

##  Bug Reports

When reporting bugs, please include:

- **Description**: Clear description of the issue
- **Steps to reproduce**: How to trigger the bug
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Environment**: OS, Go version, Docker version
- **Logs**: Relevant error messages or logs

##  Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

