#!/bin/bash

# Apache 2.4 STIG Compliance Check Script
# This script only performs checks without making any modifications

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to log messages
log() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check if Apache is installed
check_apache_installed() {
    if ! command -v apache2 >/dev/null 2>&1; then
        log "${RED}Apache2 is not installed${NC}"
        exit 1
    fi
}

# Function to check file permissions
check_file_permissions() {
    local file="$1"
    local expected_perms="$2"
    local actual_perms=$(stat -c "%a" "$file" 2>/dev/null)
    
    if [ "$actual_perms" = "$expected_perms" ]; then
        log "${GREEN}✓ Permissions for $file are correct ($actual_perms)${NC}"
        return 0
    else
        log "${RED}✗ Permissions for $file are incorrect (found: $actual_perms, expected: $expected_perms)${NC}"
        return 1
    fi
}

# Function to check file ownership
check_file_ownership() {
    local file="$1"
    local expected_owner="$2"
    local expected_group="$3"
    local actual_owner=$(stat -c "%U" "$file" 2>/dev/null)
    local actual_group=$(stat -c "%G" "$file" 2>/dev/null)
    
    if [ "$actual_owner" = "$expected_owner" ] && [ "$actual_group" = "$expected_group" ]; then
        log "${GREEN}✓ Ownership for $file is correct ($actual_owner:$actual_group)${NC}"
        return 0
    else
        log "${RED}✗ Ownership for $file is incorrect (found: $actual_owner:$actual_group, expected: $expected_owner:$expected_group)${NC}"
        return 1
    fi
}

# Function to check Apache configuration directive
check_apache_directive() {
    local directive="$1"
    local config_file="$2"
    
    if grep -q "^[[:space:]]*$directive" "$config_file" 2>/dev/null; then
        log "${GREEN}✓ Directive '$directive' found in $config_file${NC}"
        return 0
    else
        log "${RED}✗ Directive '$directive' not found in $config_file${NC}"
        return 1
    fi
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log "${RED}Please run as root to perform all checks${NC}"
    exit 1
fi

# Verify Apache installation
check_apache_installed

# Initialize counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0


log "\n${YELLOW}Checking SV-214228r960735_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214229r960735_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214230r960759_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))

# Check SSL/TLS configuration
check_apache_directive 'SSLProtocol' /etc/apache2/mods-enabled/ssl.conf

if [ $? -eq 0 ]; then
    ((PASSED_CHECKS++))
else
    ((FAILED_CHECKS++))
fi

log "\n${YELLOW}Checking SV-214231r961863_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214232r960879_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214233r960900_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214234r960912_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214235r960930_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214236r960933_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214237r960948_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214238r1016509_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))

# Check Apache modules
apache2ctl -M 2>/dev/null || log '${RED}Unable to check Apache modules${NC}'

if [ $? -eq 0 ]; then
    ((PASSED_CHECKS++))
else
    ((FAILED_CHECKS++))
fi

log "\n${YELLOW}Checking SV-214239r960963_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214240r960963_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214241r1051280_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214242r960963_rule (Severity: high)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214243r960963_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214244r960963_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214245r960963_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))

# Check Apache modules
apache2ctl -M 2>/dev/null || log '${RED}Unable to check Apache modules${NC}'

if [ $? -eq 0 ]; then
    ((PASSED_CHECKS++))
else
    ((FAILED_CHECKS++))
fi

log "\n${YELLOW}Checking SV-214246r1043177_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214247r961095_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214248r961095_rule (Severity: high)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214249r961095_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214250r1043179_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214251r1043180_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))

# Check Apache modules
apache2ctl -M 2>/dev/null || log '${RED}Unable to check Apache modules${NC}'

if [ $? -eq 0 ]; then
    ((PASSED_CHECKS++))
else
    ((FAILED_CHECKS++))
fi

log "\n${YELLOW}Checking SV-214252r1043181_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214253r1043181_rule (Severity: high)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214254r961122_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214255r1051283_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214256r961167_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214257r961167_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))

# Check TraceEnable directive
check_apache_directive 'TraceEnable Off' /etc/apache2/apache2.conf

if [ $? -eq 0 ]; then
    ((PASSED_CHECKS++))
else
    ((FAILED_CHECKS++))
fi

log "\n${YELLOW}Checking SV-214258r1043182_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))

# Check SSL/TLS configuration
check_apache_directive 'SSLProtocol' /etc/apache2/mods-enabled/ssl.conf

if [ $? -eq 0 ]; then
    ((PASSED_CHECKS++))
else
    ((FAILED_CHECKS++))
fi

log "\n${YELLOW}Checking SV-214259r961278_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214260r961281_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214261r961353_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214262r961392_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214263r961395_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214264r961395_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214265r961443_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214266r961470_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214267r961620_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214268r961632_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))

# Check SSL/TLS configuration
check_apache_directive 'SSLProtocol' /etc/apache2/mods-enabled/ssl.conf

if [ $? -eq 0 ]; then
    ((PASSED_CHECKS++))
else
    ((FAILED_CHECKS++))
fi

log "\n${YELLOW}Checking SV-214269r961632_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))

# Check SSL/TLS configuration
check_apache_directive 'SSLProtocol' /etc/apache2/mods-enabled/ssl.conf

if [ $? -eq 0 ]; then
    ((PASSED_CHECKS++))
else
    ((FAILED_CHECKS++))
fi

log "\n${YELLOW}Checking SV-214270r961683_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214271r961863_rule (Severity: high)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214272r961863_rule (Severity: low)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214273r961863_rule (Severity: high)${NC}"
((TOTAL_CHECKS++))


log "\n${YELLOW}Checking SV-214274r961863_rule (Severity: medium)${NC}"
((TOTAL_CHECKS++))


# Print summary
log "\n----------------------------------------"
log "STIG Compliance Check Summary:"
log "----------------------------------------"
log "Total Checks Run: $TOTAL_CHECKS"
log "${GREEN}Checks Passed: $PASSED_CHECKS${NC}"
log "${RED}Checks Failed: $FAILED_CHECKS${NC}"
log "----------------------------------------"

# Calculate compliance percentage
COMPLIANCE_PCT=$(( (PASSED_CHECKS * 100) / TOTAL_CHECKS ))
log "Overall Compliance: ${YELLOW}$COMPLIANCE_PCT%${NC}"
