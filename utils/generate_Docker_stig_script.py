#!/usr/bin/env python3
"""
Filter STIG checks for Docker compatibility.
This script analyzes the existing STIG compliance script and generates a Docker-compatible version
that only includes checks that make sense in a Docker container environment.
"""

import sys
import os
import json
import re
import subprocess

# Patterns that indicate a check is not compatible with Docker containers
DOCKER_INCOMPATIBLE_PATTERNS = [
    # System services that don't exist in Docker
    r'systemctl',
    r'systemd',
    r'service\s+\w+\s+status',
    r'initctl',
    r'chkconfig',
    r'is-active',
    r'is-enabled',
    r'daemon',
    r'unit file',
    
    # Kernel parameters that are managed by the host
    r'sysctl',
    r'/proc/sys',
    r'kernel\.dmesg_restrict',
    r'kernel\.randomize_va_space',
    r'net\.ipv4\.ip_forward',
    r'net\.ipv4\.tcp_syncookies',
    r'net\.ipv4\.conf\.all\.accept_redirects',
    r'net\.ipv6',
    
    # Boot and hardware related checks
    r'grub',
    r'/boot/',
    r'fips_mode',
    r'fips_enabled',
    r'x86 Ctrl-Alt-Delete',
    
    # GUI related checks (Docker containers typically don't have GUIs)
    r'X11',
    r'gdm',
    r'gnome',
    r'dconf',
    r'gsettings',
    
    # System-wide services that are typically not in containers
    r'auditd',
    r'rsyslog',
    r'cron',
    r'aide',
    r'firewall',
    r'iptables',
    r'ufw',
    r'apparmor',  # AppArmor is managed at the host level, not in containers
    
    # System files that might not exist in containers or are managed differently
    r'/etc/fstab',
    r'/etc/login\.defs',
    r'/etc/security/limits\.conf',
    r'/etc/pam\.d',
    r'/var/log/journal',
    r'/var/log/audit',
    
    # PAM and authentication modules that aren't relevant in containers
    r'libpam-pwquality',  # Password quality enforcement
    r'libpam-',           # Other PAM modules
    r'pam_',              # PAM configuration directives
    r'password quality',  # Password quality checks
    r'password strength',  # Password strength requirements
    r'password complexity',  # Password complexity requirements
    r'password history',  # Password history requirements
    
    # Sudo-related patterns that aren't relevant in containers
    r'sudo',              # Sudo command and configuration
    r'sudoers',           # Sudoers file
    r'/etc/sudoers',      # Sudoers file path
    
    # Time synchronization patterns that aren't relevant in containers
    r'chrony',            # Chrony time synchronization
    r'ntp',               # NTP time synchronization
    r'timesyncd',         # Systemd timesyncd
    r'time synchronization',  # General time sync references
    
    # SSH installation should not be a requirement for containers
    r'must have SSH installed',  # SSH installation requirement
    
    # PIV and authentication hardware that isn't relevant in containers
    r'personal identity verification',  # PIV credentials
    r'piv credentials',              # PIV credentials
    r'opensc-pkcs11',                # PIV smart card library
    r'smart card',                   # Smart card references
    
    # Session locking not relevant in containers
    r'session lock',                 # Session locking
    r'vlock',                        # Virtual console lock tool
    
    # Commands that check system-wide settings
    r'mount',
    r'lsblk',
    r'fdisk',
    r'parted',
    r'df',
    r'sestatus',
    r'getenforce',
    r'apparmor_status',
    r'aa-status',
    r'aa-enforce',
    r'aa-complain'
]

# Patterns that indicate a check is compatible with Docker containers
DOCKER_COMPATIBLE_PATTERNS = [
    # Package management
    r'apt\s+list',
    r'dpkg\s+-l',
    r'apt-cache',
    
    # File permissions and ownership
    r'find\s+/\s+',
    r'find\s+/bin\s+',
    r'find\s+/usr/bin\s+',
    r'find\s+/etc\s+',
    
    # Configuration files that are relevant in containers
    r'/etc/ssh/sshd_config',
    r'/etc/passwd',
    r'/etc/shadow',
    r'/etc/group',
    r'/etc/hosts',
    r'/etc/resolv.conf',
    
    # Security settings that apply to containers
    r'umask',
    r'permissions',
    r'password',
    r'crypto',
    r'cipher',
    r'ssh'
]

def is_docker_compatible(rule_id, title, check_content, commands):
    """
    Determine if a STIG check is compatible with Docker containers.
    
    Args:
        rule_id: The ID of the STIG rule
        title: The title of the STIG rule
        check_content: The check content description
        commands: List of commands used to check compliance
        
    Returns:
        bool: True if the check is compatible with Docker, False otherwise
    """
    # Some rules are explicitly incompatible with Docker
    if any(pattern in title.lower() for pattern in [
        "fips", "mount", "audit", "systemd", "boot", "x11", "ctrl-alt-delete",
        "pam", "password quality", "password strength", "password complexity", "sssd",
        "sudo", "security functions", "chrony", "time synchronization", "ntp",
        "must have ssh installed", "personal identity verification", "piv credentials",
        "session lock", "initiate a session lock"
    ]):
        return False
    
    # Check commands for incompatible patterns
    for cmd in commands:
        if any(re.search(pattern, cmd, re.IGNORECASE) for pattern in DOCKER_INCOMPATIBLE_PATTERNS):
            return False
    
    # If no incompatible patterns found, check for compatible patterns
    # If we have at least one compatible pattern, consider it compatible
    for cmd in commands:
        if any(re.search(pattern, cmd, re.IGNORECASE) for pattern in DOCKER_COMPATIBLE_PATTERNS):
            return True
    
    # If no commands or no compatible patterns found, check the content
    if not commands:
        # For checks without commands, analyze the check content
        if any(re.search(pattern, check_content, re.IGNORECASE) for pattern in DOCKER_INCOMPATIBLE_PATTERNS):
            return False
        if any(re.search(pattern, check_content, re.IGNORECASE) for pattern in DOCKER_COMPATIBLE_PATTERNS):
            return True
    
    # Default to incompatible if we can't determine compatibility
    return False

def fix_command_for_docker(command):
    """
    Modify commands to work better in Docker environments.
    
    Args:
        command: The original command
        
    Returns:
        str: The modified command for Docker
    """
    # Remove sudo as it's typically not needed in Docker (often running as root)
    command = re.sub(r'sudo\s+', '', command)
    
    # Replace commands that might not work in Docker
    if 'systemctl' in command:
        # Replace systemctl commands with checks for the process or config
        if 'is-active' in command or 'status' in command:
            service = re.search(r'systemctl\s+(?:is-active|status)\s+(\S+)', command)
            if service:
                service_name = service.group(1).replace('.service', '')
                return f"ps aux | grep -v grep | grep {service_name}"
        elif 'is-enabled' in command:
            # Can't really check if a service is enabled in Docker
            return "echo 'Service enable check not applicable in Docker'"
    
    return command

def generate_script_header():
    """Generate the script header with functions and initialization."""
    return """#!/bin/bash
# Docker-Compatible Ubuntu STIG Compliance Checker
# Auto-generated script to check STIG compliance in Docker containers

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Initialize counters
TOTAL=0
PASSED=0
FAILED=0
MANUAL=0
NOT_CHECKED=0
NOT_APPLICABLE=0

# Function to update counters
update_counters() {
    local result="$1"
    
    TOTAL=$((TOTAL + 1))
    
    case "$result" in
        "PASS")
            PASSED=$((PASSED + 1))
            ;;
        "FAIL")
            FAILED=$((FAILED + 1))
            ;;
        "MANUAL")
            MANUAL=$((MANUAL + 1))
            ;;
        "NOT_CHECKED")
            NOT_CHECKED=$((NOT_CHECKED + 1))
            ;;
        "NOT_APPLICABLE")
            NOT_APPLICABLE=$((NOT_APPLICABLE + 1))
            ;;
    esac
}

# Function to print rule result
print_rule_result() {
    local result="$1"
    local rule_id="$2"
    local title="$3"
    
    case "$result" in
        "PASS")
            echo -e "${GREEN}[PASS]${NC} $rule_id: $title"
            ;;
        "FAIL")
            echo -e "${RED}[FAIL]${NC} $rule_id: $title"
            ;;
        "MANUAL")
            echo -e "${YELLOW}[MANUAL]${NC} $rule_id: $title"
            ;;
        "NOT_CHECKED")
            echo -e "${MAGENTA}[NOT_CHECKED]${NC} $rule_id: $title"
            ;;
        "NOT_APPLICABLE")
            echo -e "${BLUE}[NOT_APPLICABLE]${NC} $rule_id: $title"
            ;;
    esac
}

# Function to evaluate grep command results
evaluate_grep_command() {
    local exit_code="$1"
    local output="$2"
    local requirement_type="$3"
    local command="$4"
    
    # Special case for SSH banner check
    if [[ "$command" == *"grep -ir banner /etc/ssh/sshd_config"* ]]; then
        # Check if there's an uncommented Banner line that's not 'none'
        if [[ "$output" == *"Banner "* ]] && [[ ! "$output" == *"#Banner"* ]] && [[ ! "$output" == *"Banner none"* ]]; then
            # Extract the banner file path
            local banner_file=$(echo "$output" | grep -v "^#" | grep "Banner " | awk '{print $2}' | head -1)
            if [[ -n "$banner_file" ]]; then
                echo "PASS"
                # We'll need to check the content of this file in a separate command
            else
                echo "FAIL"
                echo -e "${YELLOW}SSH banner is not properly configured${NC}" >&2
            fi
        else
            echo "FAIL"
            echo -e "${YELLOW}SSH banner is not configured or is set to 'none'${NC}" >&2
        fi
        return
    fi
    
    # For grep commands, exit code 0 means match found, 1 means no match, 2+ means error
    if [ $exit_code -eq 0 ]; then
        # Match found
        if [[ "$requirement_type" == "negative" ]]; then
            # For negative requirements, match found is bad
            echo "FAIL"
        else
            # For positive requirements, match found is good
            echo "PASS"
        fi
    elif [ $exit_code -eq 1 ]; then
        # No match found
        if [[ "$requirement_type" == "negative" ]]; then
            # For negative requirements, no match is good
            echo "PASS"
        else
            # For positive requirements, no match is bad
            echo "FAIL"
        fi
    else
        # Error occurred
        echo "NOT_CHECKED"
        echo -e "${MAGENTA}Error executing grep command${NC}" >&2
    fi
}

# Function to evaluate command result
evaluate_command_result() {
    local exit_code="$1"
    local output="$2"
    local requirement_type="$3"
    local command="$4"
    local rule_id="$5"
    
    # Special case for SSH banner content check
    if [[ "$rule_id" == "SV-270691r1066562_rule" ]] && [[ "$command" == *"cat /etc/issue.net"* ]]; then
        # Check if the banner contains required DoD text
        if [[ "$output" == *"You are accessing"* ]] && \
           [[ "$output" == *"U.S. Government"* ]] && \
           [[ "$output" == *"unauthorized access"* ]]; then
            echo "PASS"
        else
            echo "FAIL"
            echo -e "${YELLOW}SSH banner does not contain required DoD text${NC}" >&2
        fi
        return
    fi
    
    # Special case for SSH banner acknowledgement check
    if [[ "$rule_id" == "SV-270694r1066571_rule" ]] && [[ "$command" == *"cat /etc/profile.d/ssh_confirm.sh"* ]]; then
        if [ $exit_code -ne 0 ]; then
            echo "FAIL"
            echo -e "${YELLOW}SSH banner acknowledgement script not found${NC}" >&2
            return
        fi
        
        # Check if the script contains required DoD text and acknowledgement prompt
        if [[ "$output" == *"You are accessing"* ]] && \
           [[ "$output" == *"U.S. Government"* ]] && \
           [[ "$output" == *"unauthorized access"* ]] && \
           [[ "$output" == *"ACKNOWLEDGE"* ]]; then
            echo "PASS"
        else
            echo "FAIL"
            echo -e "${YELLOW}SSH banner acknowledgement script does not contain required content${NC}" >&2
        fi
        return
    fi
    
    # For grep commands
    if [[ "$command" == *"grep"* ]]; then
        evaluate_grep_command "$exit_code" "$output" "$requirement_type" "$command"
    # For package checks
    elif [[ "$command" == *"dpkg -l"* || "$command" == *"apt list"* ]]; then
        if [ $exit_code -eq 0 ]; then
            if [[ "$requirement_type" == "negative" ]]; then
                # For negative requirements, package found is bad
                echo "FAIL"
            else
                # For positive requirements, package found is good
                echo "PASS"
            fi
        else
            if [[ "$requirement_type" == "negative" ]]; then
                # For negative requirements, package not found is good
                echo "PASS"
            else
                # For positive requirements, package not found is bad
                echo "FAIL"
            fi
        fi
    elif [[ "$command" == *"systemctl"* ]]; then
        # Docker containers don't use systemd services
        echo "NOT_APPLICABLE"
    elif [[ "$command" == *"sysctl"* ]]; then
        # Docker containers don't manage kernel parameters
        echo "NOT_APPLICABLE"
    else
        # Default evaluation based on exit code
        if [ $exit_code -eq 0 ]; then
            echo "PASS"
        else
            echo "FAIL"
        fi
    fi
}
"""

def generate_summary_section():
    """Generate the summary section for the script."""
    return """
# Print summary
echo ""
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}                 Summary Report                        ${NC}"
echo -e "${CYAN}=======================================================${NC}"
echo -e "${BLUE}Total Checks:${NC} $TOTAL"
echo -e "${GREEN}Passed:${NC} $PASSED"
echo -e "${RED}Failed:${NC} $FAILED"
echo -e "${YELLOW}Manual:${NC} $MANUAL"
echo -e "${MAGENTA}Not Checked:${NC} $NOT_CHECKED"
echo -e "${BLUE}Not Applicable:${NC} $NOT_APPLICABLE"

# Calculate compliance percentage (excluding manual, not checked, and not applicable)
if [ $((PASSED + FAILED)) -gt 0 ]; then
    COMPLIANCE_PERCENT=$(( (PASSED * 100) / (PASSED + FAILED) ))
    echo -e "${BLUE}Compliance Percentage:${NC} ${COMPLIANCE_PERCENT}%"
else
    echo -e "${BLUE}Compliance Percentage:${NC} N/A (no automated checks)"
fi

echo -e "${CYAN}=======================================================${NC}"
"""

def generate_check_block(rule_id, title, check_content, commands, requirement_type, check_type):
    """Generate a shell script block for a STIG check."""
    # Format the commands as a shell script block
    command_block = ""
    
    # Special case for SSH banner and SSH-related checks
    if "ssh" in title.lower() and not "must have ssh installed" in title.lower():
        # Make SSH checks conditional on SSH being installed
        command_block = """
    # Check if SSH is installed first
    if ! dpkg -l | grep -q openssh-server; then
        # SSH is not installed, so this check is not applicable
        result="NOT_CHECKED"
        echo -e "${YELLOW}SSH is not installed, skipping this check${NC}"
    else
"""
        
        # Add the regular commands indented inside the if block
        if commands:
            for cmd in commands:
                # Add command execution and result evaluation (indented for the if block)
                command_block += f"""
        # Execute command: {cmd}
        echo -e "${{CYAN}}Executing: {cmd}${{NC}}"
        output=$({cmd} 2>&1)
        exit_code=$?
        echo "$output"
        
        # Evaluate result
        result=$(evaluate_command_result "$exit_code" "$output" "{requirement_type}" "{cmd}" "{rule_id}")
    """
        else:
            # If no commands, mark as manual check
            command_block += """
        # No automated commands available
        echo -e "${YELLOW}No automated commands available for this check${NC}"
        result="MANUAL"
        echo -e "${YELLOW}Manual verification required${NC}"
    """
        
        # Close the if block
        command_block += """
    fi
"""
    elif commands:
        # Regular case for non-SSH checks with commands
        for cmd in commands:
            # Add command execution and result evaluation
            command_block += f"""
    # Execute command: {cmd}
    echo -e "${{CYAN}}Executing: {cmd}${{NC}}"
    output=$({cmd} 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "{requirement_type}" "{cmd}" "{rule_id}")
    """
    else:
        # If no commands, mark as manual check
        command_block = """
    # No automated commands available
    echo -e "${YELLOW}No automated commands available for this check${NC}"
    result="MANUAL"
    echo -e "${YELLOW}Manual verification required${NC}"
    """
    
    # Format the full check block
    block = f"""
# =======================================================================
# {rule_id}: {title}
# =======================================================================
echo -e "${{CYAN}}=======================================================${{NC}}"
echo -e "${{CYAN}}Checking {rule_id}${{NC}}"
echo -e "${{CYAN}}Title: {title}${{NC}}"
echo -e "${{CYAN}}=======================================================${{NC}}"

check_{rule_id.replace('-', '_')}() {{
    # Check content:
    # {check_content.replace('\n', '\n    # ')}
{command_block}
    # Print result
    print_rule_result "$result" "{rule_id}" "{title}"
    
    # Update counters
    update_counters "$result"
}}

# Run the check
check_{rule_id.replace('-', '_')}

"""
    
    return block

def modify_check_block_for_docker(rule_id, title, check_content, commands, requirement_type, check_type):
    """
    Modify a STIG check block to be Docker-compatible.
    
    Args:
        rule_id: The ID of the STIG rule
        title: The title of the STIG rule
        check_content: The check content description
        commands: List of commands used to check compliance
        requirement_type: Whether this is a positive or negative requirement
        check_type: The type of check (package, service, config, etc.)
        
    Returns:
        str: The modified check block
    """
    # For Docker, modify the title to indicate Docker compatibility
    docker_title = f"[DOCKER] {title}"
    
    # Modify commands to be Docker-compatible
    docker_commands = [fix_command_for_docker(cmd) for cmd in commands]
    
    # Add a note about Docker compatibility to the check content
    docker_check_content = (
        "NOTE: This check has been modified for Docker compatibility. "
        "Some aspects of the original check may not apply in a containerized environment.\n\n"
        f"{check_content}"
    )
    
    # Generate the check block using the Docker-modified content
    return generate_check_block(rule_id, docker_title, docker_check_content, docker_commands, requirement_type, check_type)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 docker_stig_filter.py <xml_file> [output_file]")
        sys.exit(1)
    
    xml_file = sys.argv[1]
    output_file = "docker_stig_checks.sh" if len(sys.argv) < 3 else sys.argv[2]
    
    # Get all rule IDs
    try:
        rule_ids_output = subprocess.check_output(["python3", "utils/parse_stig_xml.py", xml_file, "--list-rules"], 
                                                universal_newlines=True)
        rule_ids = rule_ids_output.strip().split('\n')
    except subprocess.CalledProcessError as e:
        print(f"Error getting rule IDs: {e}")
        sys.exit(1)
    
    # Define our own functions for generating script header and summary section
    
    # Start building the shell script with header, functions, and initialization
    script_content = generate_script_header()
    
    # Add a Docker-specific header
    script_content += """
# ======================================================
# DOCKER-COMPATIBLE STIG COMPLIANCE CHECKS
# ======================================================
# This script contains only STIG checks that are compatible with Docker containers.
# Many system-level checks have been excluded as they don't apply in containerized environments.
# ======================================================

"""
    
    # Track compatible and incompatible rules
    compatible_rules = []
    incompatible_rules = []
    
    # Add each compatible rule as a separate block
    for rule_id in rule_ids:
        if not rule_id.strip():
            continue
            
        # Get rule information
        try:
            title = subprocess.check_output(["python3", "utils/parse_stig_xml.py", xml_file, rule_id, "title"], 
                                          universal_newlines=True).strip()
            check_content = subprocess.check_output(["python3", "utils/parse_stig_xml.py", xml_file, rule_id, "check_content"], 
                                                 universal_newlines=True).strip()
            commands_json = subprocess.check_output(["python3", "utils/parse_stig_xml.py", xml_file, rule_id, "commands"], 
                                                 universal_newlines=True).strip()
            requirement_type = subprocess.check_output(["python3", "utils/parse_stig_xml.py", xml_file, rule_id, "requirement_type"], 
                                                    universal_newlines=True).strip()
            check_type = subprocess.check_output(["python3", "utils/parse_stig_xml.py", xml_file, rule_id, "check_type"], 
                                              universal_newlines=True).strip()
        except subprocess.CalledProcessError as e:
            print(f"Error getting info for rule {rule_id}: {e}")
            continue
            
        # Parse commands if available
        commands = []
        if commands_json:
            try:
                commands = json.loads(commands_json)
            except json.JSONDecodeError as e:
                print(f"Error parsing commands for rule {rule_id}: {e}")
        
        # Check if this rule is compatible with Docker
        if is_docker_compatible(rule_id, title, check_content, commands):
            compatible_rules.append(rule_id)
            # Generate Docker-compatible block for this rule
            block = modify_check_block_for_docker(rule_id, title, check_content, commands, requirement_type, check_type)
            script_content += block
        else:
            incompatible_rules.append(rule_id)
    
    # Add summary section
    script_content += generate_summary_section()
    
    # Add Docker compatibility summary
    script_content += f"""
# ======================================================
# DOCKER COMPATIBILITY SUMMARY
# ======================================================
echo -e "${{CYAN}}=======================================================${{NC}}"
echo -e "${{CYAN}}       Docker Compatibility Summary                   ${{NC}}"
echo -e "${{CYAN}}=======================================================${{NC}}"
echo -e "${{BLUE}}Total STIG Rules:${{NC}} {len(compatible_rules) + len(incompatible_rules)}"
echo -e "${{GREEN}}Docker-Compatible Rules:${{NC}} {len(compatible_rules)}"
echo -e "${{RED}}Docker-Incompatible Rules:${{NC}} {len(incompatible_rules)}"
echo -e "${{CYAN}}=======================================================${{NC}}"
"""
    
    # Write to file
    try:
        with open(output_file, 'w') as f:
            f.write(script_content)
        os.chmod(output_file, 0o755)  # Make executable
        print(f"Docker-compatible STIG script written to {output_file}")
        print(f"Compatible rules: {len(compatible_rules)}/{len(compatible_rules) + len(incompatible_rules)}")
    except Exception as e:
        print(f"Error writing script: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
