#!/bin/bash

# STIG Compliance Test Suite
# This script runs test cases to verify the functionality of the OS and Docker scanning scripts
# with different output options

# Set colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Track test results
PASSED=0
FAILED=0
TOTAL=0

# Function to run a test and report results
run_test() {
    local test_script="$1"
    local test_name="$2"
    
    echo -e "\n${YELLOW}Running test: ${test_name}${NC}"
    echo "----------------------------------------"
    
    # Make the test script executable
    chmod +x "$test_script"
    
    # Run the test script
    if "$test_script"; then
        echo -e "${GREEN}PASS: ${test_name}${NC}"
        ((PASSED++))
    else
        echo -e "${RED}FAIL: ${test_name}${NC}"
        ((FAILED++))
    fi
    
    ((TOTAL++))
    echo "----------------------------------------"
}

# Create test directory if it doesn't exist
mkdir -p "$(dirname "$0")/results"

# Run all test scripts
echo -e "${YELLOW}Starting STIG Compliance Scanner Test Suite${NC}"
echo "========================================"

# OS Scanner Tests
run_test "$(dirname "$0")/test_os_scanner.sh" "OS Scanner Functionality"

# Docker Scanner Tests
run_test "$(dirname "$0")/test_docker_scanner.sh" "Docker Scanner Functionality"

# CSV Report Generation Tests
run_test "$(dirname "$0")/test_csv_output.sh" "CSV Output Functionality"

# Print summary
echo -e "\n${YELLOW}Test Summary${NC}"
echo "========================================"
echo -e "Total Tests: ${TOTAL}"
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo -e "Success Rate: $(( (PASSED * 100) / TOTAL ))%"
echo "========================================"

# Return overall success/failure
if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Please check the logs for details.${NC}"
    exit 1
fi
