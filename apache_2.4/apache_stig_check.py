#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import sys
import os

def parse_stig_xml(xml_file):
    """Parse the STIG XML file and extract check information."""
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    # Define namespace map
    ns = {
        'xccdf': 'http://checklists.nist.gov/xccdf/1.1',
        'dc': 'http://purl.org/dc/elements/1.1/'
    }
    
    checks = []
    
    # Find all Rules
    for rule in root.findall('.//xccdf:Rule', ns):
        rule_id = rule.get('id', '')
        severity = rule.get('severity', '')
        
        title = rule.find('xccdf:title', ns)
        title_text = title.text if title is not None else ''
        
        check = rule.find('.//xccdf:check-content', ns)
        check_content = check.text if check is not None else ''
        
        if check_content:  # Only include rules with actual checks
            checks.append({
                'id': rule_id,
                'severity': severity,
                'title': title_text,
                'check_content': check_content
            })
    
    return checks

def generate_check_script(checks):
    """Generate a bash script that only performs checks."""
    script = """#!/bin/bash

# Apache 2.4 STIG Compliance Check Script
# This script only performs checks without making any modifications

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

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

"""
    
    for check in checks:
        script += f"\nlog \"\\n${{YELLOW}}Checking {check['id']} (Severity: {check['severity']})${{NC}}\"\n"
        script += "((TOTAL_CHECKS++))\n\n"
        
        # Convert check content to bash commands
        check_commands = convert_check_to_bash(check['check_content'])
        if check_commands:
            script += check_commands + "\n"
            script += """
if [ $? -eq 0 ]; then
    ((PASSED_CHECKS++))
else
    ((FAILED_CHECKS++))
fi
"""
    
    script += """
# Print summary
log "\\n----------------------------------------"
log "STIG Compliance Check Summary:"
log "----------------------------------------"
log "Total Checks Run: $TOTAL_CHECKS"
log "${GREEN}Checks Passed: $PASSED_CHECKS${NC}"
log "${RED}Checks Failed: $FAILED_CHECKS${NC}"
log "----------------------------------------"

# Calculate compliance percentage
COMPLIANCE_PCT=$(( (PASSED_CHECKS * 100) / TOTAL_CHECKS ))
log "Overall Compliance: ${YELLOW}$COMPLIANCE_PCT%${NC}"
"""
    
    return script

def convert_check_to_bash(check_content):
    """Convert check content to bash verification commands."""
    if not check_content:
        return ""
        
    commands = []
    
    # File permission checks
    if "ls -l" in check_content or "permissions" in check_content.lower():
        if "/etc/apache2" in check_content:
            commands.append("# Check Apache configuration file permissions")
            commands.append("check_file_permissions /etc/apache2/apache2.conf 640")
            commands.append("check_file_permissions /etc/apache2 750")
    
    # Ownership checks
    if "root" in check_content and ("own" in check_content.lower() or "chown" in check_content.lower()):
        if "/etc/apache2" in check_content:
            commands.append("# Check Apache configuration file ownership")
            commands.append("check_file_ownership /etc/apache2/apache2.conf root root")
    
    # Configuration directive checks
    if "grep" in check_content:
        if "ServerTokens" in check_content:
            commands.append("# Check ServerTokens directive")
            commands.append("check_apache_directive 'ServerTokens Prod' /etc/apache2/apache2.conf")
        if "TraceEnable" in check_content:
            commands.append("# Check TraceEnable directive")
            commands.append("check_apache_directive 'TraceEnable Off' /etc/apache2/apache2.conf")
    
    # Module checks
    if "apache2ctl -M" in check_content or "modules" in check_content.lower():
        commands.append("# Check Apache modules")
        commands.append("apache2ctl -M 2>/dev/null || log '${RED}Unable to check Apache modules${NC}'")
    
    # SSL/TLS checks
    if "ssl" in check_content.lower() or "tls" in check_content.lower():
        commands.append("# Check SSL/TLS configuration")
        commands.append("check_apache_directive 'SSLProtocol' /etc/apache2/mods-enabled/ssl.conf")
    
    return "\n".join(commands)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <stig_xml_file>")
        sys.exit(1)
        
    xml_file = sys.argv[1]
    if not os.path.exists(xml_file):
        print(f"Error: File {xml_file} not found")
        sys.exit(1)
    
    checks = parse_stig_xml(xml_file)
    check_script = generate_check_script(checks)
    
    output_file = "apache_stig_check.sh"
    with open(output_file, "w") as f:
        f.write(check_script)
    
    os.chmod(output_file, 0o755)
    print(f"Generated check script: {output_file}")

if __name__ == "__main__":
    main()
