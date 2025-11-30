#!/bin/bash

# Bitsage Network Coordinator Test Script
# This script tests the basic functionality of the coordinator system

set -e

echo "🚀 Starting Bitsage Network Coordinator Tests"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    if [ "$status" = "PASS" ]; then
        echo -e "${GREEN}✅ PASS${NC}: $message"
    elif [ "$status" = "FAIL" ]; then
        echo -e "${RED}❌ FAIL${NC}: $message"
    elif [ "$status" = "WARN" ]; then
        echo -e "${YELLOW}⚠️  WARN${NC}: $message"
    else
        echo "ℹ️  INFO: $message"
    fi
}

# Test 1: Check if Rust is installed
echo ""
echo "📋 Test 1: Rust Environment"
echo "---------------------------"
if command -v rustc &> /dev/null; then
    print_status "PASS" "Rust is installed"
    rustc --version
else
    print_status "FAIL" "Rust is not installed"
    exit 1
fi

# Test 2: Check if Cargo is installed
echo ""
echo "📋 Test 2: Cargo Environment"
echo "----------------------------"
if command -v cargo &> /dev/null; then
    print_status "PASS" "Cargo is installed"
    cargo --version
else
    print_status "FAIL" "Cargo is not installed"
    exit 1
fi

# Test 3: Check project structure
echo ""
echo "📋 Test 3: Project Structure"
echo "----------------------------"
if [ -f "Cargo.toml" ]; then
    print_status "PASS" "Cargo.toml found"
else
    print_status "FAIL" "Cargo.toml not found"
    exit 1
fi

if [ -d "src" ]; then
    print_status "PASS" "src directory found"
else
    print_status "FAIL" "src directory not found"
    exit 1
fi

if [ -f "src/coordinator_main.rs" ]; then
    print_status "PASS" "coordinator_main.rs found"
else
    print_status "FAIL" "coordinator_main.rs not found"
    exit 1
fi

# Test 4: Check dependencies
echo ""
echo "📋 Test 4: Dependencies"
echo "----------------------"
if [ -f "Cargo.lock" ]; then
    print_status "PASS" "Cargo.lock found (dependencies resolved)"
else
    print_status "WARN" "Cargo.lock not found, will be generated on first build"
fi

# Test 5: Try to build the project
echo ""
echo "📋 Test 5: Build Test"
echo "-------------------"
print_status "INFO" "Attempting to build the project..."

if cargo check --quiet; then
    print_status "PASS" "Project compiles successfully"
else
    print_status "FAIL" "Project has compilation errors"
    echo ""
    echo "🔧 Attempting to fix common issues..."
    
    # Try to add missing dependencies
    echo "Adding common dependencies..."
    cargo add md5 toml serde_json chrono uuid || true
    
    # Try to build again
    if cargo check --quiet; then
        print_status "PASS" "Project compiles after dependency fixes"
    else
        print_status "FAIL" "Project still has compilation errors"
        echo ""
        echo "📝 Compilation errors:"
        cargo check 2>&1 | head -20
        exit 1
    fi
fi

# Test 6: Check for configuration files
echo ""
echo "📋 Test 6: Configuration"
echo "-----------------------"
if [ -d "config" ]; then
    print_status "PASS" "config directory found"
else
    print_status "WARN" "config directory not found, will be created"
    mkdir -p config
fi

# Test 7: Check for documentation
echo ""
echo "📋 Test 7: Documentation"
echo "----------------------"
if [ -f "COORDINATOR_ENHANCED.md" ]; then
    print_status "PASS" "Enhanced coordinator documentation found"
else
    print_status "WARN" "Enhanced coordinator documentation not found"
fi

if [ -f "TEST_PLAN.md" ]; then
    print_status "PASS" "Test plan documentation found"
else
    print_status "WARN" "Test plan documentation not found"
fi

# Test 8: Check for tests
echo ""
echo "📋 Test 8: Test Files"
echo "-------------------"
if [ -d "tests" ]; then
    print_status "PASS" "tests directory found"
    test_count=$(find tests -name "*.rs" | wc -l)
    print_status "INFO" "Found $test_count test files"
else
    print_status "WARN" "tests directory not found"
fi

# Test 9: Check for Docker support
echo ""
echo "📋 Test 9: Docker Support"
echo "----------------------"
if [ -f "Dockerfile" ]; then
    print_status "PASS" "Dockerfile found"
else
    print_status "WARN" "Dockerfile not found"
fi

if [ -f "docker-compose.yml" ]; then
    print_status "PASS" "docker-compose.yml found"
else
    print_status "WARN" "docker-compose.yml not found"
fi

# Test 10: Check for CI/CD
echo ""
echo "📋 Test 10: CI/CD"
echo "----------------"
if [ -f ".github/workflows/ci.yml" ] || [ -f ".gitlab-ci.yml" ] || [ -f ".circleci/config.yml" ]; then
    print_status "PASS" "CI/CD configuration found"
else
    print_status "WARN" "CI/CD configuration not found"
fi

# Summary
echo ""
echo "📊 Test Summary"
echo "=============="
echo "✅ Environment: Rust and Cargo installed"
echo "✅ Project: Basic structure present"
echo "✅ Build: Project compiles successfully"
echo "⚠️  Configuration: Some config files may be missing"
echo "⚠️  Documentation: Some docs may be missing"
echo "⚠️  Tests: Test files may need to be created"
echo "⚠️  Deployment: Docker and CI/CD configs may be missing"

echo ""
echo "🎯 Next Steps:"
echo "1. Fix any remaining compilation errors"
echo "2. Create configuration files for your environment"
echo "3. Implement unit tests for each component"
echo "4. Set up integration tests"
echo "5. Configure deployment (Docker, Kubernetes)"
echo "6. Set up monitoring and observability"

echo ""
echo "🚀 Ready to run the coordinator!"
echo "Use: cargo run --bin ciro-coordinator -- --help"
echo ""
echo "📚 For more information, see:"
echo "- COORDINATOR_ENHANCED.md for architecture details"
echo "- TEST_PLAN.md for testing strategy"
echo "- README.md for setup instructions"

print_status "PASS" "Basic coordinator system validation completed" 