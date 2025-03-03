#!/usr/bin/env python3
"""
XCCDF to Shell Script Converter

This script parses an XCCDF XML file and generates a shell script that checks
for compliance with the security requirements defined in the XCCDF file.
"""

import argparse
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime

def parse_xccdf(xccdf_file):
    """Parse the XCCDF XML file and extract rules."""
    try:
        tree = ET.parse(xccdf_file)
        root = tree.getroot()
        
        # Extract namespace
        ns_match = re.match(r'\{(.*?)\}', root.tag)
        if ns_match:
            ns = ns_match.group(1)
            ns_map = {'xccdf': ns}
        else:
            ns_map = {}
        
        # Extract benchmark information
        benchmark_info = {
            'title': get_element_text(root, './/xccdf:title', ns_map) or 'Unknown Title',
            'version': get_element_text(root, './/xccdf:version', ns_map) or 'Unknown Version',
            'release_date': get_element_text(root, './/xccdf:status', ns_map) or 'Unknown Date',
            'publisher': get_element_text(root, './/xccdf:publisher', ns_map) or 'Unknown Publisher'
        }
        
        # Extract rules
        rules = []
        for rule in root.findall('.//xccdf:Rule', ns_map):
            if rule.get('selected', 'true') != 'false':
                rule_id = rule.get('id', '')
                rule_title = get_element_text(rule, './xccdf:title', ns_map) or 'No Title'
                rule_severity = rule.get('severity', 'unknown')
                
                # Extract and clean description (remove XML tags)
                rule_description = get_element_text(rule, './xccdf:description', ns_map) or ''
                rule_description = re.sub(r'<.*?>', '', rule_description)  # Remove XML tags
                rule_description = rule_title  # Use the title as the description for simplicity
                
                # Extract check content
                check_content = get_element_text(rule, './/xccdf:check-content', ns_map) or ''
                
                # Extract fix text
                fix_text = get_element_text(rule, './/xccdf:fixtext', ns_map) or ''
                
                rules.append({
                    'id': rule_id,
                    'title': rule_title,
                    'severity': rule_severity,
                    'description': rule_description,
                    'check': check_content,
                    'fix': fix_text
                })
        
        print(f"Extracted {len(rules)} rules from the XCCDF file")
        return benchmark_info, rules
    
    except Exception as e:
        print(f"Error parsing XCCDF file: {e}")
        return {}, []

def get_element_text(element, xpath, ns_map):
    """Get text from an XML element, handling the case where the element doesn't exist."""
    el = element.find(xpath, ns_map)
    return el.text.strip() if el is not None and el.text else ''

def extract_commands(check_content):
    """Extract commands from check content text."""
    if not check_content:
        return []
    
    commands = []
    
    # Common command patterns
    patterns = [
        r'\$ sudo ([^|\n\r]+)',  # Commands with sudo
        r'\$ ([^|\n\r]+)',       # Commands with $ prompt
        r'# ([^|\n\r]+)',        # Commands with # prompt
        r'Run[:\s]+[\"\']?([^\"\';\n\r]+)[\"\']?',  # "Run: command"
        r'command[:\s]+[\"\']([^\"\';\n\r]+)[\"\']',  # "command: 'command'"
        r'run the command[:\s]+[\"\']?([^\"\';\n\r]+)[\"\']?',  # "run the command: command"
        r'Verify [^:]*?:[^\n]*?\n\s*[\$#]\s+([^\n\r]+)',  # Verification commands
        r'verify[:\s]+[\"\']?([^\"\';\n\r]+)[\"\']?'  # "verify: command"
    ]
    
    # Command prefixes to specifically look for
    command_prefixes = [
        'grep', 'find', 'ls', 'cat', 'awk', 'stat', 'systemctl', 'service',
        'dpkg', 'apt', 'auditctl', 'ausearch', 'df', 'ps', 'sestatus',
        'mount', 'sysctl', 'chkconfig'
    ]
    
    # Extract using patterns
    for pattern in patterns:
        matches = re.finditer(pattern, check_content, re.MULTILINE)
        for match in matches:
            cmd = match.group(1).strip()
            if cmd and not any(cmd.startswith(x) for x in ['echo ', 'exit ', 'reboot']):
                commands.append(cmd)
    
    # Look for specific command prefixes
    lines = check_content.split('\n')
    for line in lines:
        line = line.strip()
        for prefix in command_prefixes:
            if re.match(r'^' + prefix + r'\s', line) and not line.startswith('$') and not line.startswith('#'):
                commands.append(line)
    
    # Remove duplicates while preserving order
    unique_commands = []
    for cmd in commands:
        if cmd not in unique_commands:
            unique_commands.append(cmd)
    
    return unique_commands

def generate_bash_script(benchmark_info, rules, output_file=None):
    """Generate a bash script to check compliance with the rules."""
    script = """#!/bin/bash

# STIG Compliance Check Script
# Generated: {date}
# Source: {source}

# Benchmark Information:
# Title: {title}
# Version: {version}
# Release Date: {release_date}
# Publisher: {publisher}

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
BLUE='\\033[0;34m'
NC='\\033[0m' # No Color

# Results array
declare -A results
declare -A titles

# Trap Ctrl+C and cleanup
trap cleanup INT

cleanup() {{
    echo -e "\\n\\nScript interrupted. Generating report with current results..."
    generate_report
    exit 1
}}

# Helper function to determine if a rule has a negative requirement
is_negative_requirement() {{
    local description="$1"
    
    # Check for common negative requirement phrases
    if [[ "$description" == *"must not"* ]] || 
       [[ "$description" == *"must be disabled"* ]] || 
       [[ "$description" == *"must be removed"* ]] || 
       [[ "$description" == *"must be uninstalled"* ]] || 
       [[ "$description" == *"must be prohibited"* ]]; then
        return 0  # True in bash
    fi
    
    return 1  # False in bash
}}

# Enhanced run check function that considers rule description
run_check_enhanced() {{
    local cmd="$1"
    local rule_description="$2"
    
    # Check if command contains placeholders (e.g., <user>)
    if [[ "$cmd" == *"<"*">"* ]]; then
        echo "manual"
        return
    fi
    
    # Extract the command binary (first word before space or pipe)
    local binary=$(echo "$cmd" | awk '{{print $1}}' | cut -d '|' -f1)
    
    # Check if the command exists
    if ! command -v $binary &>/dev/null; then
        echo "not checked"
        return
    fi
    
    # Execute command with a timeout and capture output
    output=$(timeout 5s bash -c "$cmd" 2>&1)
    local exit_code=$?
    
    # Handle timeout condition
    if [ $exit_code -eq 124 ]; then
        # Command timed out
        echo "manual"
        return
    fi
    
    # Check for "command not found" in the output
    if [[ "$output" == *"command not found"* ]] || [[ "$output" == *"No such file or directory"* ]]; then
        echo "not checked"
        return
    fi
    
    # Determine if this is a negative requirement
    if is_negative_requirement "$rule_description"; then
        # For package checks with negative requirements
        if [[ "$cmd" == *"dpkg -l | grep"* ]] || [[ "$cmd" == *"apt list --installed | grep"* ]]; then
            # If package is found (exit code 0), it's a fail
            if [ $exit_code -eq 0 ]; then
                echo "fail"
                return
            # If package is not found (exit code 1), it's a pass
            elif [ $exit_code -eq 1 ]; then
                echo "pass"
                return
            fi
        fi
        
        # For service checks with negative requirements
        if [[ "$cmd" == *"systemctl is-active"* ]] || [[ "$cmd" == *"systemctl is-enabled"* ]]; then
            # If service is active/enabled (exit code 0), it's a fail
            if [ $exit_code -eq 0 ]; then
                echo "fail"
                return
            # If service is not active/enabled (exit code non-0), it's a pass
            else
                echo "pass"
                return
            fi
        fi
        
        # For other negative requirements, invert the standard logic
        if [ $exit_code -eq 0 ]; then
            echo "fail"
        else
            echo "pass"
        fi
    else
        # Standard logic for positive requirements
        if [ $exit_code -eq 0 ]; then
            echo "pass"
        elif [ $exit_code -eq 1 ] && [ -z "$output" ]; then
            echo "pass"
        else
            echo "fail"
        fi
    fi
}}

# Run a check command and determine the system's compliance
run_check() {{
    local cmd="$1"
    local rule_description="$2"
    
    # Call the enhanced run check function
    run_check_enhanced "$cmd" "$rule_description"
}}

# Log the result of a check
log_result() {{
    local rule_id="$1"
    local status="$2"
    local title="$3"
    
    if [ "$status" == "pass" ]; then
        echo -e "${{GREEN}}[PASS]${{NC}} $rule_id: $title"
        results["$rule_id"]="pass"
    elif [ "$status" == "manual" ]; then
        echo -e "${{YELLOW}}[MANUAL CHECK NEEDED]${{NC}} $rule_id: $title"
        results["$rule_id"]="manual"
    elif [ "$status" == "not checked" ]; then
        echo -e "${{BLUE}}[NOT CHECKED]${{NC}} $rule_id: $title"
        results["$rule_id"]="not checked"
    else
        echo -e "${{RED}}[FAIL]${{NC}} $rule_id: $title"
        results["$rule_id"]="fail"
    fi
    titles["$rule_id"]="$title"
}}

# Generate a summary report
generate_report() {{
    # Generate summary report
    echo -e "\\nSTIG Compliance Summary Report"
    echo "================================"
    echo -e "Total Rules Checked: ${{#results[@]}}"
    
    # Count results by type
    pass_count=0
    fail_count=0
    manual_count=0
    not_checked_count=0
    
    for status in "${{results[@]}}"; do
        case "$status" in
            "pass")
                ((pass_count++))
                ;;
            "fail")
                ((fail_count++))
                ;;
            "manual")
                ((manual_count++))
                ;;
            "not checked")
                ((not_checked_count++))
                ;;
        esac
    done
    
    echo -e "Passed: $pass_count"
    echo -e "Failed: $fail_count"
    echo -e "Manual Checks Needed: $manual_count"
    echo -e "Not Checked: $not_checked_count"

    # Create results directory
    RESULTS_DIR="stig_results"
    mkdir -p "$RESULTS_DIR"
    
    # Save detailed results to a file
    echo "Rule ID,Title,Status" > "$RESULTS_DIR/results.csv"
    
    for rule_id in "${{!results[@]}}"; do
        echo "$rule_id,\\"${{titles[$rule_id]}}\\",\\"${{results[$rule_id]}}\\"" >> "$RESULTS_DIR/results.csv"
    done
    
    echo -e "\\nDetailed results have been saved to $RESULTS_DIR/results.csv"
}}

# Rule check functions
""".format(
        date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        source=os.path.basename(output_file) if output_file else 'Unknown',
        title=benchmark_info.get('title', 'Unknown'),
        version=benchmark_info.get('version', 'Unknown'),
        release_date=benchmark_info.get('release_date', 'Unknown'),
        publisher=benchmark_info.get('publisher', 'Unknown')
    )
    
    # Generate rule check functions
    for rule in rules:
        if rule['check'] and extract_commands(rule['check']):
            rule_id = rule['id']
            title = rule['title'].replace('"', '\\"')
            description = rule['description'].replace('"', '\\"')
            
            script += f"""
# {rule_id}: {title}
check_{rule_id.replace('-', '_')}() {{
    local status="fail"
"""
            
            for cmd in extract_commands(rule['check']):
                # Escape any quotes in the command
                escaped_cmd = cmd.replace('"', '\\"')
                # Remove sudo prefix as we're running as root
                escaped_cmd = escaped_cmd.replace('sudo ', '')
                
                script += f"""
    # Run command: {cmd}
    status=$(run_check "{escaped_cmd}" "{description}")
    if [ "$status" == "manual" ]; then
        break
    fi
"""
            
            script += f"""
    # Log result
    log_result "{rule_id}" "$status" "{title}"
}}
"""
    
    # Add main execution section
    script += "\n# Main execution\necho \"Starting STIG compliance checks...\"\n"
    
    for rule in rules:
        if rule['check'] and extract_commands(rule['check']):
            script += f"check_{rule['id'].replace('-', '_')}\n"
    
    # Add final report generation
    script += "\n# Generate final report\ngenerate_report\n"
    
    # Save to file if output_file is specified
    if output_file:
        with open(output_file, 'w') as f:
            f.write(script)
        os.chmod(output_file, 0o755)  # Make the script executable
        print(f"Generated compliance check script: {output_file}")
        print(f"Run with sudo to perform all checks properly: sudo ./{output_file}")
    
    return script

def main():
    parser = argparse.ArgumentParser(description='Convert XCCDF XML to shell script for compliance checking')
    parser.add_argument('xccdf_file', help='Path to the XCCDF XML file')
    parser.add_argument('--output', '-o', help='Output shell script file (default: <input_filename>_compliance_check.sh)')
    args = parser.parse_args()
    
    # Parse XCCDF file
    benchmark_info, rules = parse_xccdf(args.xccdf_file)
    
    # Generate output filename based on input XML filename if not specified
    if not args.output:
        input_filename = os.path.splitext(os.path.basename(args.xccdf_file))[0]
        args.output = f'{input_filename}_compliance_check.sh'
    
    # Generate bash script
    generate_bash_script(benchmark_info, rules, args.output)

if __name__ == "__main__":
    main()