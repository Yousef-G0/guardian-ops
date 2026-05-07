#!/bin/bash

set -e

echo "  Guardian-Ops - Setup Script"
echo "======================================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running on WSL
if grep -qi microsoft /proc/version; then
    echo -e "${GREEN}✓${NC} Running on WSL"
else
    echo -e "${YELLOW}⚠${NC}  Not running on WSL, but continuing..."
fi

# Check prerequisites
echo ""
echo "Checking prerequisites..."

# Check Go
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}')
    echo -e "${GREEN}✓${NC} Go installed: $GO_VERSION"
else
    echo -e "${RED}✗${NC} Go not found. Installing..."
    wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo -e "${GREEN}✓${NC} Go installed"
fi

# Check Docker
if command -v docker &> /dev/null; then
    echo -e "${GREEN}✓${NC} Docker installed"
else
    echo -e "${YELLOW}⚠${NC}  Docker not found. Install with: curl -fsSL https://get.docker.com | sh"
fi

# Check Rust (for advanced features)
if command -v cargo &> /dev/null; then
    RUST_VERSION=$(cargo --version | awk '{print $2}')
    echo -e "${GREEN}✓${NC} Rust installed: $RUST_VERSION"
    RUST_AVAILABLE=true
else
    echo -e "${YELLOW}⚠${NC}  Rust not found. Advanced features will be unavailable."
    echo -e "${YELLOW}   Install with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh${NC}"
    RUST_AVAILABLE=false
fi

# Build Go applications
echo ""
echo "Building applications..."

echo "  → Building Security API..."
cd cmd/api
go mod download
go build -o ../../bin/security-api main.go
cd ../..
echo -e "${GREEN}✓${NC} Security API built: ./bin/security-api"

# Build advanced version if Rust is available
if [ "$RUST_AVAILABLE" = true ]; then
    echo ""
    echo "  → Building Advanced Security API (Rust integration)..."
    echo "    Building Rust security analyzer..."
    cd rust-security-analyzer
    cargo build --release
    echo "    Rust library built successfully"
    cd ..

    echo "    Building Go API with Rust FFI integration..."
    export CGO_LDFLAGS="-L$(pwd)/rust-security-analyzer/target/release -lsecurity_analyzer -ldl"
    cd cmd/api
    go build -o ../../bin/security-api-advanced main.go
    cd ../..
    echo -e "${GREEN}✓${NC} Advanced Security API built: ./bin/security-api-advanced"
    echo -e "${GREEN}✓${NC} Advanced features available: AST-based analysis, multi-language support"
else
    echo -e "${YELLOW}⚠${NC}  Skipping advanced build (Rust not available)"
fi

echo "  → Building Runtime Agent..."
cd cmd/agent
go build -o ../../bin/runtime-agent main.go
cd ../..
echo -e "${GREEN}✓${NC} Runtime Agent built: ./bin/runtime-agent"

# Create directories
echo ""
echo "Creating directories..."
mkdir -p logs
mkdir -p /var/log/guardian-ops 2>/dev/null || sudo mkdir -p /var/log/guardian-ops
echo -e "${GREEN}✓${NC} Directories created"

# Create environment file
echo ""
echo "Creating environment configuration..."
cat > .env << 'EOF'
# GitHub Configuration
GITHUB_REPO=owner/repo
GITHUB_TOKEN=your_github_token_here

# Monitoring Configuration
MONITORED_PROCESS=
CHECK_INTERVAL=30

# API Configuration
SECURITY_API_URL=http://localhost:8080
EOF

echo -e "${GREEN}✓${NC} Environment file created: .env"
echo -e "${YELLOW}⚠${NC}  Please edit .env and add your GitHub token"

# Create systemd service files (optional)
echo ""
echo "Creating systemd service files..."

cat > devsecops-api.service << 'EOF'
[Unit]
Description=Guardian-Ops - Security API
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$PWD
ExecStart=$PWD/bin/security-api
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

cat > devsecops-agent.service << 'EOF'
[Unit]
Description=Guardian-Ops - Runtime Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$PWD
EnvironmentFile=$PWD/.env
ExecStart=$PWD/bin/runtime-agent
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}✓${NC} Service files created"
echo ""
echo "To install as system services:"
echo "  sudo cp devsecops-api.service /etc/systemd/system/"
echo "  sudo cp devsecops-agent.service /etc/systemd/system/"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable devsecops-api devsecops-agent"
echo "  sudo systemctl start devsecops-api devsecops-agent"

# Test the API
echo ""
echo "Testing Security API..."
./bin/security-api &
API_PID=$!
sleep 3

if curl -s http://localhost:8080/health > /dev/null; then
    echo -e "${GREEN}✓${NC} Security API is responding"
    
    # Run a test scan
    echo "  → Running test scan..."
    SCAN_RESULT=$(curl -s -X POST http://localhost:8080/scan \
        -H "Content-Type: application/json" \
        -d "{
            \"repo_path\": \".\",
            \"branch\": \"main\",
            \"commit_hash\": \"test\"
        }")
    
    RISK_SCORE=$(echo "$SCAN_RESULT" | jq -r '.risk_score')
    echo -e "${GREEN}✓${NC} Test scan complete. Risk score: $RISK_SCORE/100"
else
    echo -e "${RED}✗${NC} Security API not responding"
fi

kill $API_PID 2>/dev/null || true

# Summary
echo ""
echo "======================================"
echo -e "${GREEN} Setup Complete!${NC}"
echo "======================================"
echo ""
echo "Available binaries:"
echo "  ./bin/security-api              # Basic security API"
if [ "$RUST_AVAILABLE" = true ]; then
    echo "  ./bin/security-api-advanced     # Advanced API with Rust AST analysis"
fi
echo "  ./bin/runtime-agent             # Runtime monitoring agent"
echo ""
echo "Next steps:"
echo "1. Edit .env and configure your GitHub token"
echo "2. Start the Security API:"
if [ "$RUST_AVAILABLE" = true ]; then
    echo "   ./bin/security-api              # Basic version"
    echo "   ./bin/security-api-advanced     # Advanced version (recommended)"
else
    echo "   ./bin/security-api"
fi
echo ""
echo "3. Start the Runtime Agent:"
echo "   sudo ./bin/runtime-agent"
echo ""
echo "4. Or use Docker:"
echo "   docker-compose up -d"
echo ""
echo "5. Set up GitHub Actions:"
echo "   - Push this repo to GitHub"
echo "   - The workflows in .github/workflows/ will activate"
echo "   - Add GITHUB_TOKEN secret if using self-hosted runner"
echo ""
if [ "$RUST_AVAILABLE" = true ]; then
    echo "Advanced Features Available:"
    echo "• AST-based security analysis for Rust, Go, Python, JavaScript"
    echo "• Advanced vulnerability detection beyond regex patterns"
    echo "• Data flow analysis for injection vulnerabilities"
    echo "• Cryptographic weakness detection"
    echo "• Parallel processing with Rayon"
    echo ""
    echo "Use the /advanced-scan endpoint for deep analysis:"
    echo "  curl -X POST http://localhost:8080/advanced-scan \\"
    echo "       -H 'Content-Type: application/json' \\"
    echo "       -d '{\"repo_path\": \"/path/to/code\"}'"
    echo ""
fi
echo "For more information, see README.md"
