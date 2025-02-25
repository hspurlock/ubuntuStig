#!/usr/bin/env python3

import argparse
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple

class STIGChecker:
    def __init__(self, xccdf_file: str):
        self.xccdf_file = xccdf_file
        self.rules = []
        self.parse_xccdf()

    def parse_xccdf(self):
        """Parse the XCCDF file and extract rules, checks, and fixes."""
        tree = ET.parse(self.xccdf_file)
        root = tree.getroot()
        
        # Handle XML namespace
        ns = {'xccdf': 'http://checklists.nist.gov/xccdf/1.1'}
        
        # Find all Rule elements
        for rule in root.findall('.//xccdf:Rule', ns):
            rule_id = rule.get('id')
            title = rule.find('xccdf:title', ns).text if rule.find('xccdf:title', ns) is not None else ''
            severity = rule.get('severity')
            
            # Get check content
            check = rule.find('.//xccdf:check-content', ns)
            check_content = check.text if check is not None else ''
            
            # Get fix content
            fix = rule.find('.//xccdf:fixtext', ns)
            fix_content = fix.text if fix is not None else ''
            
            self.rules.append({
                'id': rule_id,
                'title': title,
                'severity': severity,
                'check': check_content,
                'fix': fix_content
            })

    def extract_commands(self, check_content: str) -> List[str]:
        """Extract commands from check content."""
        commands = []
        for line in check_content.split('\n'):
            line = line.strip()
            if line.startswith('$'):
                # Remove the leading $ and trim
                cmd = line[1:].strip()
                commands.append(cmd)
        return commands

    def generate_bash_script(self) -> str:
        """Generate a bash script to perform the checks."""
        script_header = '''#!/bin/bash

# STIG Compliance Check Script
# Generated from XCCDF file: ''' + os.path.basename(self.xccdf_file) + '''

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root to perform all checks properly."
    echo "Please run with: sudo $0"
    exit 1
fi

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

# Results array
declare -A results

# Trap Ctrl+C and cleanup
trap cleanup INT

cleanup() {
    echo -e "\\n\\nScript interrupted. Generating report with current results..."
    generate_report
    exit 1
}

run_check() {
    local cmd="$1"
    
    # Check if command contains placeholders (e.g., <user>)
    if [[ "$cmd" == *"<"*">"* ]]; then
        echo "manual"
        return
    fi
    
    # Execute command with a timeout
    timeout 5s bash -c "$cmd" &>/dev/null
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        echo "pass"
    elif [ $exit_code -eq 124 ]; then
        # Command timed out
        echo "manual"
    else
        echo "fail"
    fi
}

log_result() {
    local rule_id="$1"
    local status="$2"
    local title="$3"
    
    if [ "$status" == "pass" ]; then
        echo -e "${GREEN}[PASS]${NC} $rule_id: $title"
        results["$rule_id"]="pass"
    elif [ "$status" == "manual" ]; then
        echo -e "${YELLOW}[MANUAL CHECK NEEDED]${NC} $rule_id: $title"
        results["$rule_id"]="manual"
    else
        echo -e "${RED}[FAIL]${NC} $rule_id: $title"
        results["$rule_id"]="fail"
    fi
}

generate_report() {
    # Generate summary report
    echo -e "\\nSTIG Compliance Summary Report"
    echo "================================"
    echo -e "Total Rules Checked: ${#results[@]}"
    pass_count=$(echo "${results[@]}" | tr ' ' '\\n' | grep -c "pass" || echo 0)
    manual_count=$(echo "${results[@]}" | tr ' ' '\\n' | grep -c "manual" || echo 0)
    fail_count=$(echo "${results[@]}" | tr ' ' '\\n' | grep -c "fail" || echo 0)
    echo -e "Passed: $pass_count"
    echo -e "Failed: $fail_count"
    echo -e "Manual Checks Needed: $manual_count"

    # Create results directory with proper permissions
    RESULTS_DIR="stig_results"
    mkdir -p "$RESULTS_DIR"
    chmod 755 "$RESULTS_DIR"

    # Save detailed results to JSON
    (
        echo "{"
        first=true
        for rule_id in "${!results[@]}"; do
            if [ "$first" = true ]; then
                first=false
            else
                echo ","
            fi
            echo -n "  \\"$rule_id\\": {\\"status\\": \\"${results[$rule_id]}\\"}"
        done
        echo
        echo "}"
    ) > "$RESULTS_DIR/results.json"
    chmod 644 "$RESULTS_DIR/results.json"

    echo -e "\\nDetailed results have been saved to $RESULTS_DIR/results.json"
}
'''

        # Add check functions for each rule
        check_functions = ""
        for rule in self.rules:
            if not rule['check']:
                continue

            commands = self.extract_commands(rule['check'])
            if not commands:
                continue

            check_function = f"""
# {rule['id']}: {rule['title']}
check_{rule['id'].replace('-', '_')}() {{
    local status="fail"
"""
            
            for cmd in commands:
                # Escape any quotes in the command
                escaped_cmd = cmd.replace('"', '\\"')
                # Remove sudo as we're already running as root
                escaped_cmd = escaped_cmd.replace('sudo ', '')
                check_function += f"""
    # Run command: {cmd}
    status=$(run_check "{escaped_cmd}")
    if [ "$status" == "manual" ]; then
        break
    fi
"""

            check_function += f"""
    # Log result
    log_result "{rule['id']}" "$status" "{rule['title']}"
}}
"""
            check_functions += check_function

        # Add main execution section
        main_section = "\n# Execute all checks\n"
        for rule in self.rules:
            if not rule['check']:
                continue
            main_section += f"check_{rule['id'].replace('-', '_')}\n"

        # Add final report generation
        footer = "\n# Generate final report\ngenerate_report\n"
        
        return script_header + check_functions + main_section + footer

def main():
    parser = argparse.ArgumentParser(description='Generate STIG compliance check script from XCCDF file')
    parser.add_argument('xccdf_file', help='Path to the XCCDF XML file')
    parser.add_argument('--output', '-o', help='Output bash script file')
    args = parser.parse_args()

    # Generate output filename based on input XML filename if not specified
    if not args.output:
        input_filename = os.path.splitext(os.path.basename(args.xccdf_file))[0]
        args.output = f'{input_filename}_stig_check.sh'

    checker = STIGChecker(args.xccdf_file)
    script = checker.generate_bash_script()
    
    with open(args.output, 'w') as f:
        f.write(script)
    
    # Make the script executable
    os.chmod(args.output, 0o755)
    print(f"Generated compliance check script: {args.output}")
    print(f"Run with sudo to perform all checks properly: sudo ./{args.output}")

if __name__ == '__main__':
    main()
