#!/bin/bash

# Test CSV Report Generation Feature
# This script tests the CSV report generation functionality

# Set up test environment
TEST_DIR="$(dirname "$0")"
RESULTS_DIR="${TEST_DIR}/results"
MAIN_DIR="$(dirname "$TEST_DIR")"
mkdir -p "$RESULTS_DIR"

# Set colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Function to check if a file exists and is not empty
check_file() {
    local file="$1"
    local description="$2"
    
    if [ -f "$file" ] && [ -s "$file" ]; then
        echo -e "${GREEN}✓ $description exists and is not empty${NC}"
        return 0
    else
        echo -e "${RED}✗ $description does not exist or is empty${NC}"
        return 1
    fi
}

# Function to check if CSV file has expected headers
check_csv_headers() {
    local csv_file="$1"
    local expected_headers="Rule ID,Title,Status,Details"
    
    if head -n 1 "$csv_file" | grep -q "$expected_headers"; then
        echo -e "${GREEN}✓ CSV file has correct headers${NC}"
        return 0
    else
        echo -e "${RED}✗ CSV file does not have correct headers${NC}"
        echo "Expected: $expected_headers"
        echo "Found: $(head -n 1 "$csv_file")"
        return 1
    fi
}

# Function to check if CSV file has expected content
check_csv_content() {
    local csv_file="$1"
    
    # Check if file has at least 5 rows (header + 4 data rows)
    if [ "$(wc -l < "$csv_file")" -ge 5 ]; then
        echo -e "${GREEN}✓ CSV file has sufficient content${NC}"
        
        # Check if file has rule IDs in expected format (SV-XXXXXX)
        if grep -q '"SV-[0-9]\+r[0-9]\+_rule"' "$csv_file"; then
            echo -e "${GREEN}✓ CSV file contains properly formatted rule IDs${NC}"
            return 0
        else
            echo -e "${RED}✗ CSV file does not contain properly formatted rule IDs${NC}"
            return 1
        fi
    else
        echo -e "${RED}✗ CSV file does not have sufficient content${NC}"
        return 1
    fi
}

echo "Testing CSV Report Generation..."

# Test 1: Run a minimal scan with CSV output
TEST_OUTPUT="${RESULTS_DIR}/csv_test_results.txt"
TEST_CSV="${RESULTS_DIR}/csv_test_results.csv"

echo "Running minimal scan with CSV output..."
# Use a small subset of checks for faster testing
cd "$MAIN_DIR" && ./RUN_SCAN.sh ./ubuntu_24-04_v1r1.sh "$TEST_OUTPUT" --csv --test-mode 5 > /dev/null 2>&1

# Check if output files exist
check_file "$TEST_OUTPUT" "Text output file" || exit 1
check_file "$TEST_CSV" "CSV output file" || exit 1

# Check CSV file structure and content
check_csv_headers "$TEST_CSV" || exit 1
check_csv_content "$TEST_CSV" || exit 1

# Test 2: Check Docker scan with CSV output
DOCKER_TEST_OUTPUT="${RESULTS_DIR}/docker_csv_test_results.txt"
DOCKER_TEST_CSV="${RESULTS_DIR}/docker_csv_test_results.csv"

echo "Running Docker scan with CSV output..."
# Check if Docker is available
if command -v docker &> /dev/null && docker ps &> /dev/null; then
    # Use a running container or create a test container
    CONTAINER_ID=$(docker ps -q | head -n 1)
    
    if [ -n "$CONTAINER_ID" ]; then
        echo "Using existing container: $CONTAINER_ID"
        
        # Copy scripts to container
        docker cp "$MAIN_DIR/docker_ubuntu_24-04_v1r1.sh" "$CONTAINER_ID:/tmp/"
        docker cp "$MAIN_DIR/RUN_SCAN.sh" "$CONTAINER_ID:/tmp/"
        
        # Run test in container
        docker exec "$CONTAINER_ID" bash -c "cd /tmp && chmod +x *.sh && ./RUN_SCAN.sh ./docker_ubuntu_24-04_v1r1.sh /tmp/docker_test.txt --csv --test-mode 5" > /dev/null 2>&1
        
        # Copy results back
        docker cp "$CONTAINER_ID:/tmp/docker_test.txt" "$DOCKER_TEST_OUTPUT"
        docker cp "$CONTAINER_ID:/tmp/docker_test.csv" "$DOCKER_TEST_CSV"
        
        # Check if output files exist
        check_file "$DOCKER_TEST_OUTPUT" "Docker text output file" || exit 1
        check_file "$DOCKER_TEST_CSV" "Docker CSV output file" || exit 1
        
        # Check CSV file structure and content
        check_csv_headers "$DOCKER_TEST_CSV" || exit 1
        check_csv_content "$DOCKER_TEST_CSV" || exit 1
    else
        echo -e "${YELLOW}⚠ No running Docker containers found, skipping Docker CSV test${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Docker not available, skipping Docker CSV test${NC}"
fi

echo -e "${GREEN}All CSV report generation tests passed!${NC}"
exit 0
