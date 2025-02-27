#!/usr/bin/env python3

import argparse
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple
from datetime import datetime

class STIGChecker:
    def __init__(self, xccdf_file: str):
        self.xccdf_file = xccdf_file
        self.rules = []
        self.benchmark_info = {
            'title': '',
            'description': '',
            'version': '',
            'release_date': '',
            'publisher': ''
        }
        self.parse_xccdf()

    def parse_xccdf(self):
        """Parse the XCCDF file and extract rules, checks, and fixes."""
        tree = ET.parse(self.xccdf_file)
        root = tree.getroot()
        
        # Handle XML namespace
        ns = {'xccdf': 'http://checklists.nist.gov/xccdf/1.1'}
        
        # Extract benchmark information
        benchmark = root.find('.//xccdf:Benchmark', ns) or root
        
        if benchmark is not None:
            self.benchmark_info['title'] = benchmark.find('.//xccdf:title', ns).text if benchmark.find('.//xccdf:title', ns) is not None else 'STIG Compliance Benchmark'
            self.benchmark_info['version'] = benchmark.get('version') or ''
            
            description = benchmark.find('.//xccdf:description', ns)
            self.benchmark_info['description'] = description.text if description is not None else ''
            
            # Try to find publisher or creator information
            publisher = benchmark.find('.//xccdf:publisher', ns) or benchmark.find('.//xccdf:creator', ns)
            self.benchmark_info['publisher'] = publisher.text if publisher is not None else 'Unknown'
            
            # Try to find release date information
            status = benchmark.find('.//xccdf:status', ns)
            if status is not None and 'date' in status.attrib:
                self.benchmark_info['release_date'] = status.get('date')
        
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
        """Extract commands from check content.
        
        This method uses several patterns to identify command lines in STIG check content,
        including lines starting with:
        - $ (common shell prompt)
        - # (root shell prompt)
        - sudo (commands requiring elevated privileges)
        - grep, find, awk, cat, ls (common commands)
        - systemctl, service (service management)
        - verification commands like "verify" followed by commands
        
        It also attempts to handle multi-line commands connected with backslashes or pipes.
        
        Args:
            check_content: The text content of a STIG check
            
        Returns:
            A list of extracted commands
        """
        commands = []
        current_command = ""
        in_multi_line = False
        
        common_command_prefixes = [
            'grep', 'find', 'awk', 'sed', 'cat', 'ls', 'ps', 'netstat', 'systemctl',
            'ausearch', 'auditctl', 'stat', 'chown', 'chmod', 'chgrp', 'mount',
            'service', 'apt', 'dpkg', 'rpm', 'yum', 'dnf', 'sysctl', 'uname',
            'check', 'verify'
        ]
        
        shell_prompt_patterns = ['$', '#', '>', '%']
        
        lines = check_content.split('\n')
        for i, line in enumerate(lines):
            stripped_line = line.strip()
            
            # Skip empty lines
            if not stripped_line:
                continue
                
            # Continue collecting multi-line command
            if in_multi_line:
                current_command += " " + stripped_line
                
                # Check if this is the end of the multi-line command
                if not (stripped_line.endswith('\\') or stripped_line.endswith('|') or 
                        stripped_line.endswith('&&') or stripped_line.endswith('||')):
                    in_multi_line = False
                    commands.append(current_command)
                    current_command = ""
                continue
            
            # Check for lines starting with shell prompts
            prompt_match = False
            for prompt in shell_prompt_patterns:
                if stripped_line.startswith(prompt + ' '):
                    cmd = stripped_line[len(prompt) + 1:].strip()
                    if cmd:
                        if cmd.endswith('\\') or cmd.endswith('|') or cmd.endswith('&&') or cmd.endswith('||'):
                            current_command = cmd
                            in_multi_line = True
                        else:
                            commands.append(cmd)
                    prompt_match = True
                    break
            
            if prompt_match:
                continue
                
            # Check for lines starting with sudo
            if stripped_line.startswith('sudo '):
                if stripped_line.endswith('\\') or stripped_line.endswith('|') or stripped_line.endswith('&&') or stripped_line.endswith('||'):
                    current_command = stripped_line
                    in_multi_line = True
                else:
                    commands.append(stripped_line)
                continue
            
            # Check for common command prefixes
            for prefix in common_command_prefixes:
                if (stripped_line.startswith(prefix + ' ') or 
                    ' ' + prefix + ' ' in stripped_line[:20]):  # Look for command in first 20 chars
                    
                    # Avoid collecting text that mentions commands but isn't actually a command
                    skip_patterns = ['verify that', 'check if', 'ensure that', 'should show', 'should return', 'should contain']
                    if any(pattern in stripped_line.lower() for pattern in skip_patterns):
                        continue
                    
                    # Try to extract just the command part if there's explanatory text
                    command_parts = stripped_line.split('. ', 1)
                    command_to_add = command_parts[-1] if len(command_parts) > 1 else stripped_line
                    
                    if command_to_add.endswith('\\') or command_to_add.endswith('|') or command_to_add.endswith('&&') or command_to_add.endswith('||'):
                        current_command = command_to_add
                        in_multi_line = True
                    else:
                        commands.append(command_to_add)
                    break
            
            # Look for verification instructions that might contain commands
            if 'run the following command' in stripped_line.lower():
                # Try to get the command from the next line
                if i + 1 < len(lines):
                    next_line = lines[i + 1].strip()
                    if next_line and not any(next_line.startswith(p) for p in ['if ', 'then ', 'else ', 'fi ']):
                        commands.append(next_line)
        
        # Add final multi-line command if we ended with one
        if current_command:
            commands.append(current_command)
        
        # Filter out obvious non-commands and clean up commands
        filtered_commands = []
        for cmd in commands:
            # Skip if too short - likely not a real command
            if len(cmd) < 3:
                continue
                
            # Skip if it's just words without command syntax
            if not any(char in cmd for char in ['/', '-', '|', '>', '<', '=']):
                # But allow common single commands
                if not any(cmd.startswith(prefix) for prefix in common_command_prefixes):
                    continue
            
            # Clean up the command
            cmd = cmd.replace('\\', ' ').strip()  # Replace trailing backslashes
            filtered_commands.append(cmd)
            
        return filtered_commands

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

# Benchmark information
BENCHMARK_TITLE="''' + self.benchmark_info['title'].replace('"', '\\"') + '''"
BENCHMARK_DESC="''' + self.benchmark_info['description'].replace('"', '\\"') + '''"
BENCHMARK_VERSION="''' + self.benchmark_info['version'].replace('"', '\\"') + '''"
BENCHMARK_PUBLISHER="''' + self.benchmark_info['publisher'].replace('"', '\\"') + '''"
BENCHMARK_DATE="''' + self.benchmark_info['release_date'].replace('"', '\\"') + '''"

# Results array
declare -A results
declare -A titles

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
    
    # Extract the command binary (first word before space or pipe)
    local binary=$(echo "$cmd" | awk '{print $1}' | cut -d '|' -f1)
    
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
    
    # Handle commands that return 1 but have no output - mark as pass
    if [ $exit_code -eq 1 ] && [ -z "$output" ]; then
        echo "pass"
        return
    fi
    
    # Check for "command not found" in the output
    if [[ "$output" == *"command not found"* ]] || [[ "$output" == *"No such file or directory"* ]]; then
        echo "not checked"
        return
    fi
    
    # Default handling
    if [ $exit_code -eq 0 ]; then
        echo "pass"
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
    elif [ "$status" == "not checked" ]; then
        echo -e "${YELLOW}[NOT CHECKED]${NC} $rule_id: $title"
        results["$rule_id"]="not checked"
    else
        echo -e "${RED}[FAIL]${NC} $rule_id: $title"
        results["$rule_id"]="fail"
    fi
    titles["$rule_id"]="$title"
}

generate_report() {
    # Generate summary report
    echo -e "\\nSTIG Compliance Summary Report"
    echo "================================"
    echo -e "Total Rules Checked: ${#results[@]}"
    pass_count=$(echo "${results[@]}" | tr ' ' '\\n' | grep -c "pass" || echo 0)
    manual_count=$(echo "${results[@]}" | tr ' ' '\\n' | grep -c "manual" || echo 0)
    fail_count=$(echo "${results[@]}" | tr ' ' '\\n' | grep -c "fail" || echo 0)
    not_checked_count=$(echo "${results[@]}" | tr ' ' '\\n' | grep -c "not checked" || echo 0)
    echo -e "Passed: $pass_count"
    echo -e "Failed: $fail_count"
    echo -e "Manual Checks Needed: $manual_count"
    echo -e "Not Checked: $not_checked_count"

    # Create results directory with proper permissions
    RESULTS_DIR="stig_results"
    mkdir -p "$RESULTS_DIR"
    chmod 755 "$RESULTS_DIR"

    # Generate HTML report
    cat > "$RESULTS_DIR/report.html" << 'EOL'
<!DOCTYPE html>
<html>
<head>
    <title>STIG Compliance Report</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 20px; 
            line-height: 1.6;
            color: #333;
        }
        h1, h2 { 
            color: #2c3e50; 
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }
        .summary { 
            background: #f8f9fa; 
            padding: 20px; 
            border-radius: 8px; 
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .pass { color: #28a745; }
        .fail { color: #dc3545; }
        .manual { color: #ffc107; }
        .not-checked { color: #6c757d; }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th, td { 
            padding: 12px 15px; 
            text-align: left; 
            border-bottom: 1px solid #dee2e6; 
        }
        th { 
            background: #f8f9fa; 
            font-weight: bold;
            color: #2c3e50;
        }
        tr:hover { background: #f8f9fa; }
        .status-badge {
            padding: 6px 12px;
            border-radius: 4px;
            font-weight: bold;
            display: inline-block;
            min-width: 80px;
            text-align: center;
        }
        .status-pass { background: #d4edda; color: #155724; }
        .status-fail { background: #f8d7da; color: #721c24; }
        .status-manual { background: #fff3cd; color: #856404; }
        .status-not-checked { background: #e9ecef; color: #495057; }
        .timestamp {
            margin-top: 20px;
            color: #6c757d;
            font-style: italic;
        }
        .title-cell {
            max-width: 600px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .header-info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 5px solid #2c3e50;
        }
        .header-info h2 {
            margin-top: 0;
            color: #2c3e50;
            border-bottom: none;
        }
        .header-info p {
            margin: 5px 0;
        }
        .header-meta {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            font-size: 0.9em;
            color: #6c757d;
        }
        .header-meta div {
            margin-right: 20px;
            margin-bottom: 10px;
        }
        .header-meta strong {
            color: #2c3e50;
        }
    </style>
</head>
<body>
    <h1>STIG Compliance Report</h1>
EOL

    # Add benchmark information header
    cat >> "$RESULTS_DIR/report.html" << EOL
    <div class="header-info">
        <h2>${BENCHMARK_TITLE}</h2>
        <p>${BENCHMARK_DESC}</p>
        <div class="header-meta">
            <div><strong>Version:</strong> ${BENCHMARK_VERSION}</div>
            <div><strong>Publisher:</strong> ${BENCHMARK_PUBLISHER}</div>
            <div><strong>Release Date:</strong> ${BENCHMARK_DATE}</div>
            <div><strong>Scan Date:</strong> $(date)</div>
            <div><strong>Hostname:</strong> $(hostname)</div>
            <div><strong>OS:</strong> $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')</div>
        </div>
    </div>
EOL

    # Add summary section
    cat >> "$RESULTS_DIR/report.html" << EOL
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Rules Checked:</strong> ${#results[@]}</p>
        <p class="pass"><strong>Passed:</strong> $pass_count</p>
        <p class="fail"><strong>Failed:</strong> $fail_count</p>
        <p class="manual"><strong>Manual Checks Needed:</strong> $manual_count</p>
        <p class="not-checked"><strong>Not Checked:</strong> $not_checked_count</p>
    </div>
    <h2>Detailed Results</h2>
    <table>
        <tr>
            <th>Rule ID</th>
            <th>Title</th>
            <th>Status</th>
        </tr>
EOL

    # Add results to the HTML table
    for rule_id in "${!results[@]}"; do
        status="${results[$rule_id]}"
        title="${titles[$rule_id]}"
        case $status in
            "pass")
                status_class="status-pass"
                ;;
            "fail")
                status_class="status-fail"
                ;;
            "manual")
                status_class="status-manual"
                ;;
            "not checked")
                status_class="status-not-checked"
                ;;
        esac
        echo "        <tr>" >> "$RESULTS_DIR/report.html"
        echo "            <td>$rule_id</td>" >> "$RESULTS_DIR/report.html"
        echo "            <td class='title-cell'>$title</td>" >> "$RESULTS_DIR/report.html"
        echo "            <td><span class='status-badge $status_class'>${status^^}</span></td>" >> "$RESULTS_DIR/report.html"
        echo "        </tr>" >> "$RESULTS_DIR/report.html"
    done

    # Add footer with timestamp
    cat >> "$RESULTS_DIR/report.html" << EOL
    </table>
    <p class="timestamp">Report generated on $(date)</p>
</body>
</html>
EOL

    chmod 644 "$RESULTS_DIR/report.html"

    echo -e "\\nDetailed results have been saved to $RESULTS_DIR/report.html"
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
