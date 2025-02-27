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
        """Generate a Bash script to check STIG compliance."""
        # Header with usage information, colors, and trap
        benchmark_title = self.benchmark_info['title'].replace('"', '\\"') if 'title' in self.benchmark_info else "Unknown"
        benchmark_version = self.benchmark_info['version'].replace('"', '\\"') if 'version' in self.benchmark_info else "Unknown"
        benchmark_date = self.benchmark_info['release_date'].replace('"', '\\"') if 'release_date' in self.benchmark_info else "Unknown"
        benchmark_publisher = self.benchmark_info['publisher'].replace('"', '\\"') if 'publisher' in self.benchmark_info else "Unknown"
        benchmark_description = self.benchmark_info['description'].replace('"', '\\"') if 'description' in self.benchmark_info else "Unknown"
        
        script_header = f'''#!/bin/bash

# STIG Compliance Check Script
# Generated automatically by STIG Checker Tool

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root to perform all checks"
   exit 1
fi

# Define colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[0;33m'
NC='\\033[0m' # No Color

# Handle interrupt
trap 'echo -e "\\n${{RED}}Script interrupted by user${{NC}}"; exit 1' INT

# Initialize arrays for results
declare -A results
declare -A titles

# Benchmark information
BENCHMARK_TITLE="{benchmark_title}"
BENCHMARK_VERSION="{benchmark_version}"
BENCHMARK_DATE="{benchmark_date}"
BENCHMARK_PUBLISHER="{benchmark_publisher}"
BENCHMARK_DESC="{benchmark_description}"

echo "Starting STIG compliance checks..."
echo "Benchmark: $BENCHMARK_TITLE ($BENCHMARK_VERSION)"
echo "Publisher: $BENCHMARK_PUBLISHER"
echo "Date: $BENCHMARK_DATE"

run_check() {{
    local cmd="$1"
    local context="${{2:-positive}}"  # positive or negative context
    
    # Check if command contains placeholders or needs manual intervention
    if [[ "$cmd" == *"<"*">"* || "$cmd" == *"manually verify"* || "$cmd" == *"manual"* ]]; then
        echo "manual"
        return
    fi
    
    # Capture command output for inspection
    output=$(timeout 15s bash -c "$cmd" 2>&1)
    local exit_code=$?
    
    # Check for timeout
    if [ $exit_code -eq 124 ]; then
        echo "manual"
        return
    fi
    
    # Save the command output to a temp file for analysis
    echo "$output" > /tmp/cmd_output.txt
    
    # Keep original output (first 200 chars) for logging
    local short_output="${{output:0:200}}"
    if [ ${{#output}} -gt 200 ]; then
        short_output+="..."
    fi
    echo "Command output (truncated): $short_output"
    
    # Interpret results based on command type and context
    if [[ "$cmd" == *"grep"* ]]; then
        # For grep commands:
        # Exit code 0 = pattern found, 1 = not found
        # In negative context (shouldn't exist), 1 is PASS
        # In positive context (should exist), 0 is PASS
        if [[ "$context" == "negative" && $exit_code -eq 1 ]]; then
            echo "pass"  # Pattern shouldn't exist and wasn't found (exit code 1)
        elif [[ "$context" == "positive" && $exit_code -eq 0 ]]; then
            echo "pass"  # Pattern should exist and was found (exit code 0)
        else
            echo "fail"
        fi
    elif [[ "$cmd" == *"find"* ]]; then
        # For find commands:
        # Exit code 0 with output = files found
        # No output usually means nothing found
        if [[ "$context" == "negative" && -z "$output" ]]; then
            echo "pass"  # Should not find files and none found
        elif [[ "$context" == "positive" && ! -z "$output" ]]; then
            echo "pass"  # Should find files and some found
        else
            echo "fail"
        fi
    elif [[ "$cmd" == *"systemctl is-enabled"* || "$cmd" == *"systemctl --quiet is-enabled"* ]]; then
        # For systemctl is-enabled commands
        if [[ "$context" == "negative" && $exit_code -ne 0 ]]; then
            echo "pass"  # Service should not be enabled and isn't (non-zero exit)
        elif [[ "$context" == "positive" && $exit_code -eq 0 ]]; then
            echo "pass"  # Service should be enabled and is (zero exit)
        else
            echo "fail"
        fi
    elif [[ "$cmd" == *"systemctl is-active"* || "$cmd" == *"systemctl --quiet is-active"* ]]; then
        # For systemctl is-active commands
        if [[ "$context" == "negative" && $exit_code -ne 0 ]]; then
            echo "pass"  # Service should not be active and isn't (non-zero exit)
        elif [[ "$context" == "positive" && $exit_code -eq 0 ]]; then
            echo "pass"  # Service should be active and is (zero exit)
        else
            echo "fail"
        fi
    else
        # Try to intelligently determine correct outcome
        if [[ "$context" == "negative" ]]; then
            # In negative checking, often non-zero exit code is good
            if [[ $exit_code -ne 0 ]]; then
                echo "pass"
            else
                echo "fail"
            fi
        else
            # Default case - positive checking
            if [[ $exit_code -eq 0 ]]; then
                echo "pass"
            else
                echo "fail"
            fi
        fi
    fi
}}

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
    else
        echo -e "${{RED}}[FAIL]${{NC}} $rule_id: $title"
        results["$rule_id"]="fail"
    fi
    titles["$rule_id"]="$title"
}}

generate_report() {{
    echo -e "\\n\\n--- Final Report ---"
    echo -e "Benchmark: $BENCHMARK_TITLE ($BENCHMARK_VERSION)"
    echo -e "Release Date: $BENCHMARK_DATE"
    echo -e "Publisher: $BENCHMARK_PUBLISHER"
    echo -e "Description: $BENCHMARK_DESC"
    echo -e "\\nResults:"
    for rule_id in "${{!results[@]}}"; do
        echo -e "  $rule_id: ${{results[$rule_id]}} - ${{titles[$rule_id]}}"
    done
}}
'''

        # Add check functions for each rule
        check_functions = ""
        for rule in self.rules:
            if 'check' not in rule or not rule['check']:
                continue

            commands = self.extract_commands(rule['check'])
            if not commands:
                continue

            check_function = f"""
# {rule['id']}: {rule['title']}
check_{rule['id'].replace('-', '_')}() {{
    echo -e "\\n\\nChecking rule {rule['id']}: {rule['title']}"
"""
            
            for cmd in commands:
                # Look for context in check_content to determine if this is checking for presence or absence
                cmd_context = "positive"  # Default to positive checking
                check_lower = rule['check'].lower()
                
                if any(phrase in check_lower for phrase in [
                    "should not exist", "must not exist", "shall not exist", 
                    "should not be enabled", "must not be enabled", "should be disabled",
                    "should not be running", "must not be running", "should be masked",
                    "should not have", "must not have", "shall not have",
                    "should be uninstalled", "must be uninstalled"
                ]):
                    cmd_context = "negative"  # Checking for absence
                
                # Escape any quotes in the command
                escaped_cmd = cmd.replace('"', '\\"')
                # Remove sudo as we're already running as root
                escaped_cmd = escaped_cmd.replace('sudo ', '')
                
                # Add the command execution
                check_function += f'\n    echo "Running: {cmd}"'
                check_function += f'\n    result=$(run_check "{escaped_cmd}" "{cmd_context}")'
                check_function += f'\n    if [ "$result" != "manual" ]; then'
                check_function += f'\n        log_result "{rule["id"]}" "$result" "{rule["title"]}"'
                check_function += f'\n        if [ "$result" == "pass" ]; then'
                check_function += f'\n            return 0'
                check_function += f'\n        fi'
                check_function += f'\n    else'
                check_function += f'\n        log_result "{rule["id"]}" "manual" "{rule["title"]}"'
                check_function += f'\n        return 0'
                check_function += f'\n    fi'

            # If we get here, all commands have been run and none passed
            check_function += f"""
    # If none of the checks passed, mark as fail
    log_result "{rule['id']}" "fail" "{rule['title']}"
}}
"""
            check_functions += check_function

        # Add main execution section
        main_section = "\n# Execute all checks\n"
        for rule in self.rules:
            if 'check' not in rule or not rule['check']:
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
