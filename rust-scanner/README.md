# Rust Secret Scanner

A high-performance secret detection scanner written in Rust, designed to complement the Go-based Guardian-Ops security platform.

## Features

- **Fast Pattern Matching**: Uses Rust's regex engine for efficient secret detection
- **Parallel Processing**: Leverages Rayon for concurrent file scanning
- **Advanced Confidence Scoring**: Entropy-based analysis and context-aware detection
- **Comprehensive Patterns**: Supports 15+ secret types including AWS, GitHub, JWT, API keys
- **False Positive Reduction**: Smart filtering based on context and entropy

## Supported Secret Types

- AWS Access Keys and Secrets
- GitHub and GitLab tokens
- JWT and Bearer tokens
- Stripe, Twilio, SendGrid API keys
- Slack and Discord tokens
- Google and Azure API keys
- Private keys and generic API keys
- Database URLs and passwords

## Usage

```bash
# Build the scanner
cargo build --release

# Scan a directory
./target/release/rust-scanner /path/to/repository

# Output: JSON with detected secrets
```

## Integration with Go API

The Rust scanner can be integrated with the existing Go API through:

1. **FFI (Foreign Function Interface)**: Call Rust functions from Go
2. **Separate Service**: Run as a microservice and communicate via HTTP
3. **File-based**: Write results to files for the Go API to consume

## Performance Benefits

- **Memory Efficient**: Lower memory footprint than Go regex operations
- **CPU Optimized**: SIMD-accelerated regex matching
- **Concurrent**: Parallel file processing for large codebases
- **Zero-cost Abstractions**: Rust's performance without runtime overhead

## Testing

```bash
cargo test
```

## Example Output

```json
{
  "secrets": [
    {
      "file": "config/production.env",
      "line": 15,
      "secret_type": "AWS_KEY",
      "severity": "CRITICAL",
      "matched_text": "AKIA************EXAMPLE",
      "confidence": 0.95
    }
  ]
}
```