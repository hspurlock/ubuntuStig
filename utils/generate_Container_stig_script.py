#!/usr/bin/env python3
"""
Generate a shell script with each STIG check as a separate block of code.
Improved version with functions to reduce code duplication.
"""

import sys
import os
import json
import subprocess
import re

# List of commands and services that are incompatible with Docker containers
DOCKER_INCOMPATIBLE_COMMANDS = [
    # System management
    'systemctl',
    'systemd',
    'service ',
    'initctl',
    'upstart',
    'init ',
    'telinit',
    'shutdown',
    'reboot',
    'poweroff',
    'halt',
    
    # Kernel and hardware
    'sysctl',
    'modprobe',
    'insmod',
    'rmmod',
    'lsmod',
    'dmesg',
    'uname -r',
    'grub-',
    'update-grub',
    
    # Hardware tools
    'lspci',
    'lsusb',
    'lshw',
    'dmidecode',
    'hdparm',
    'fdisk',
    'parted',
    'mount ',
    'umount',
    
    # Audit system
    'auditd',
    'auditctl',
    'ausearch',
    'aureport',
    
    # Firewall
    'firewalld',
    'ufw',
    'iptables',
    'ip6tables',
    'firewall-cmd',
    
    # Filesystem
    'cryptsetup',
    'fsck',
    'e2fsck',
    'resize2fs',
    'tune2fs',
    
    # Security frameworks
    'apparmor',
    'selinux',
    
    # SSH-related commands
    'sshd',
    'ssh_config',
    'sshd_config',
    
    # PAM-related commands
    'pam-auth',
    'pam.d',
    'pamconf',
    'authconfig',
]

# Function to determine if a STIG check is compatible with Docker
def is_docker_compatible(rule_id, title, check_content, commands):
    """
    Determine if a STIG check is compatible with Docker containers by checking
    if it uses commands or references services that don't apply in containers.
    
    Args:
        rule_id: The ID of the STIG rule
        title: The title of the STIG rule
        check_content: The check content description
        commands: List of commands used to check compliance
        
    Returns:
        bool: True if the check is compatible with Docker, False otherwise
    """
    # First, check the check_content for incompatible commands
    for incompatible_cmd in DOCKER_INCOMPATIBLE_COMMANDS:
        if re.search(r'\b' + re.escape(incompatible_cmd) + r'\b', check_content, re.IGNORECASE):
            return False
    
    # Then check the extracted commands
    for cmd in commands:
        if not cmd.strip():
            continue
            
        if any(incompatible_cmd in cmd for incompatible_cmd in DOCKER_INCOMPATIBLE_COMMANDS):
            return False
    
    # Check title for incompatible keywords
    incompatible_title_keywords = [
        'boot', 'reboot', 'startup', 'shutdown',
        'kernel', 'module', 'hardware', 'physical',
        'bios', 'uefi', 'grub', 'audit', 'auditd',
        'fips', 'systemd', 'systemctl', 'service',
        'mount', 'filesystem', 'partition', 'disk',
        # Explicitly exclude AIDE-related checks
        'aide', 'integrity', 'file integrity',
        # Explicitly exclude PAM-related checks
        'pam', 'authentication', 'smart card', 'smartcard', 'pkcs11', 'pkcs', 'pki'
    ]
    
    for keyword in incompatible_title_keywords:
        if re.search(r'\b' + keyword + r'\b', title, re.IGNORECASE):
            return False
    
    # Check content for incompatible keywords and patterns
    incompatible_content_keywords = [
        'systemctl', 'systemd', 'service', 'init.d',
        'boot', 'reboot', 'kernel', 'module',
        'hardware', 'physical', 'bios', 'uefi',
        'grub', 'audit', 'auditd', 'fips',
        'mount', 'filesystem', 'partition', 'disk',
        'removable media', 'usb', 'cdrom', 'firewall',
        'ufw', 'iptables', 'apparmor', 'selinux',
        'shutdown', 'halt', 'poweroff', 'initctl',
        'journalctl', 'journald', 'dmesg', 'modprobe',
        'lsmod', 'insmod', 'rmmod', 'cryptsetup',
        'fsck', 'e2fsck', 'resize2fs', 'tune2fs',
        'lspci', 'lsusb', 'lshw', 'dmidecode',
        'hdparm', 'fdisk', 'parted',
        # Explicitly exclude AIDE-related checks
        'aide', 'integrity', 'file integrity',
        # Explicitly exclude PAM-related checks
        'pam', 'pam_', 'pam.d', 'pamconf', 'pam_pkcs11', 'pam_unix', 'pam_faillock',
        'pam_tally2', 'pam_access', 'pam_lastlog', 'pam_pwquality', 'pam_cracklib',
        'authentication', 'smart card', 'smartcard', 'pkcs11', 'pkcs', 'pki'
    ]
    
    # Check both the check content and the commands for incompatible keywords
    for keyword in incompatible_content_keywords:
        # Check in check content
        if re.search(r'\b' + keyword + r'\b', check_content, re.IGNORECASE):
            return False
            
        # Also check in commands
        for cmd in commands:
            if not cmd.strip():
                continue
                
            if re.search(r'\b' + keyword + r'\b', cmd, re.IGNORECASE):
                return False
    
    # Check for specific file paths that don't exist or are not relevant in Docker
    incompatible_file_paths = [
        '/boot/', '/etc/default/grub', '/etc/fstab',
        '/etc/systemd/', '/lib/systemd/', '/run/systemd/',
        '/etc/init/', '/etc/init.d/', '/etc/inittab',
        '/proc/sys/kernel/', '/sys/kernel/', 
        '/etc/sysctl', '/etc/modprobe',
        '/etc/udev/', '/dev/shm', '/etc/audisp/',
        '/etc/audit/', '/var/log/audit/', '/etc/security/audit'
    ]
    
    for path in incompatible_file_paths:
        if path in check_content:
            return False
    
    # Check for specific services that don't exist in Docker
    incompatible_services = [
        'auditd', 'systemd-journald', 'rsyslog', 'syslog',
        'firewalld', 'ufw', 'iptables', 'apparmor',
        'selinux', 'aidecheck', 'aide.timer', 'chrony',
        'ntpd', 'timesyncd', 'kdump', 'ctrl-alt-del',
        'emergency', 'rescue', 'halt', 'reboot',
        'shutdown', 'suspend', 'hibernate', 'sleep'
    ]
    
    # Check both the check content and the commands for incompatible services
    for service in incompatible_services:
        # Check in the check content
        service_pattern = r'\b' + service + r'(\s+service|\.[a-z]+)?\b'
        if re.search(service_pattern, check_content, re.IGNORECASE):
            return False
            
        # Also check in the commands
        for cmd in commands:
            if not cmd.strip():
                continue
                
            if re.search(service_pattern, cmd, re.IGNORECASE):
                return False
    
    # Check for specific graphical interface related checks (not applicable in Docker)
    gui_patterns = [
        r'\bgnome\b', r'\bx11\b', r'\bxorg\b', r'\bxserver\b',
        r'\bdisplay manager\b', r'\blightdm\b', r'\bgdm\b',
        r'\bsddm\b', r'\bxdm\b', r'\bscreensaver\b',
        r'\bdesktop\b', r'\bgsettings\b', r'\bdconf\b'
    ]
    
    for pattern in gui_patterns:
        if re.search(pattern, check_content, re.IGNORECASE):
            return False
    
    # If we've made it this far, the check is likely compatible with Docker
    return True

# Function to fix problematic commands
def fix_command(command, rule_id):
    # Fix for SV-270708r1066613_rule - X11Forwarding check
    if rule_id == "SV-270708r1066613_rule" and "grep -ir x11forwarding /etc/ssh/sshd_config*" in command:
        # The issue is with the closing quote in the second grep command
        if "grep -v \"^" in command and not command.endswith('"'):
            return command + '"'
    
    # Special case for the maxlogins check
    if "maxlogins" in command and ("'^[^#]" in command or "\"^[^#]" in command):
        # For the specific maxlogins check, use a hardcoded command without eval
        # This ensures the command is executed directly without shell interpretation issues
        return "grep -r -s \"^[^#].*maxlogins\" /etc/security/limits.conf /etc/security/limits.d/*.conf"
    
    # General case for grep commands with regex patterns in single quotes
    if command.startswith("grep ") and "'" in command:
        # For any grep command with square brackets or other special regex chars
        if "[" in command or "]" in command:
            # Split the command into parts: grep, options, pattern, and files
            parts = command.split("'")
            if len(parts) >= 3:
                # parts[0] contains 'grep -options ', parts[1] contains the pattern, parts[2] contains ' files'
                grep_and_options = parts[0].strip()
                pattern = parts[1]
                files = parts[2].strip()
                
                # Escape special regex characters for shell evaluation
                escaped_pattern = pattern
                for char in ['[', ']', '^', '$', '*', '+', '?', '.', '(', ')']:
                    escaped_pattern = escaped_pattern.replace(char, f"\\{char}")
                
                # Reconstruct the command with proper escaping
                return f"{grep_and_options}'{escaped_pattern}'{files}"
    
    return command

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate_blocks_improved.py <xml_file> [output_file]")
        sys.exit(1)
    
    xml_file = sys.argv[1]
    output_file = "stig_blocks.sh" if len(sys.argv) < 3 else sys.argv[2]
    
    # Get all rule IDs and filter for Docker compatibility
    try:
        rule_ids_output = subprocess.check_output(["python3", "utils/parse_stig_xml.py", xml_file, "--list-rules"], 
                                                  universal_newlines=True)
        all_rule_ids = rule_ids_output.strip().split('\n')
        
        # Filter rule IDs for Docker compatibility
        rule_ids = []
        for rule_id in all_rule_ids:
            # Get the rule details to check compatibility
            try:
                # Get rule information using the same approach as in the main script generation
                title = subprocess.check_output(["python3", "utils/parse_stig_xml.py", xml_file, rule_id, "title"], 
                                            universal_newlines=True).strip()
                check_content = subprocess.check_output(["python3", "utils/parse_stig_xml.py", xml_file, rule_id, "check_content"], 
                                                   universal_newlines=True).strip()
                commands_json = subprocess.check_output(["python3", "utils/parse_stig_xml.py", xml_file, rule_id, "commands"], 
                                                  universal_newlines=True).strip()
                
                # Parse commands if available
                commands = []
                if commands_json:
                    try:
                        commands = json.loads(commands_json)
                    except json.JSONDecodeError:
                        # If there's an error parsing JSON, continue with empty commands list
                        pass
                
                # Check if rule is compatible with Docker
                if is_docker_compatible(rule_id, title, check_content, commands):
                    rule_ids.append(rule_id)
                    
            except subprocess.CalledProcessError:
                # Skip rules that can't be processed
                continue
                
        print(f"Filtered {len(all_rule_ids)} rules down to {len(rule_ids)} Docker-compatible rules", file=sys.stderr)
        
    except subprocess.CalledProcessError as e:
        print(f"Error getting rule IDs: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Start building the shell script with header, functions, and initialization
    script_content = generate_script_header()
    
    # Add each rule as a separate block
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
            print(f"Error getting info for rule {rule_id}: {e}", file=sys.stderr)
            continue
            
        # Parse commands if available
        commands = []
        if commands_json:
            try:
                commands = json.loads(commands_json)
            except json.JSONDecodeError as e:
                print(f"Error parsing commands for rule {rule_id}: {e}", file=sys.stderr)
        
        # Generate block for this rule
        block = generate_check_block(rule_id, title, check_content, commands, requirement_type, check_type)
        script_content += block
    
    # Add summary section
    script_content += generate_summary_section()
    
    # Write to file
    try:
        with open(output_file, 'w') as f:
            f.write(script_content)
        os.chmod(output_file, 0o755)  # Make executable
        print(f"Script written to {output_file}", file=sys.stderr)
    except Exception as e:
        print(f"Error writing script: {e}", file=sys.stderr)
        sys.exit(1)

def generate_script_header():
    """Generate the script header with functions and initialization."""
    return """#!/bin/bash
# Ubuntu STIG Compliance Checker
# Auto-generated script to check STIG compliance

# Color definitions
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[0;33m'
BLUE='\\033[0;34m'
MAGENTA='\\033[0;35m'
CYAN='\\033[0;36m'
NC='\\033[0m' # No Color

# Initialize counters
TOTAL=0
PASSED=0
FAILED=0
MANUAL=0
NOT_CHECKED=0

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
    
    # Special case for TCP syncookies check
    if [[ "$command" == *"net.ipv4.tcp_syncookies"* ]] && [ $exit_code -eq 2 ] && [[ "$output" != "" ]]; then
        # Special case for TCP syncookies grep check
        # If we got output but exit code 2, check if uncommented setting exists
        if [[ "$output" == *"net.ipv4.tcp_syncookies=1"* ]] || [[ "$output" == *"net.ipv4.tcp_syncookies = 1"* ]]; then
            # Found uncommented setting with value 1
            if [[ "$requirement_type" == "negative" ]]; then
                echo "FAIL"
            else
                echo "PASS"
            fi
        elif [[ "$output" == *"#net.ipv4.tcp_syncookies"* ]]; then
            # Only commented settings found
            if [[ "$requirement_type" == "negative" ]]; then
                echo "PASS"
            else
                echo "FAIL"
                echo -e "${YELLOW}TCP syncookies setting is commented out in configuration files${NC}" >&2
            fi
        else
            # No settings found
            if [[ "$requirement_type" == "negative" ]]; then
                echo "PASS"
            else
                echo "FAIL"
                echo -e "${YELLOW}TCP syncookies setting not found in configuration files${NC}" >&2
            fi
        fi
    # Special case for kernel.dmesg_restrict check
    elif [[ "$command" == *"kernel.dmesg_restrict"* ]] && [ $exit_code -eq 2 ] && [[ "$output" != "" ]]; then
        # Special case for kernel.dmesg_restrict grep check
        # If we got output but exit code 2, check if uncommented setting exists
        if [[ "$output" == *"kernel.dmesg_restrict=1"* ]] || [[ "$output" == *"kernel.dmesg_restrict = 1"* ]]; then
            # Found uncommented setting with value 1
            if [[ "$requirement_type" == "negative" ]]; then
                echo "FAIL"
            else
                echo "PASS"
            fi
        elif [[ "$output" == *"#kernel.dmesg_restrict"* ]]; then
            # Only commented settings found
            if [[ "$requirement_type" == "negative" ]]; then
                echo "PASS"
            else
                echo "FAIL"
                echo -e "${YELLOW}kernel.dmesg_restrict setting is commented out in configuration files${NC}" >&2
            fi
        else
            # No settings found
            if [[ "$requirement_type" == "negative" ]]; then
                echo "PASS"
            else
                echo "FAIL"
                echo -e "${YELLOW}kernel.dmesg_restrict setting not found in configuration files${NC}" >&2
            fi
        fi
    # For grep commands, exit code 0 means match found, 1 means no match, 2+ means error
    elif [ $exit_code -eq 0 ]; then
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
        # Error in grep command (e.g., file not found)
        echo "NOT_CHECKED"
    fi
}

# Function to evaluate package check results
evaluate_package_check() {
    local exit_code="$1"
    local requirement_type="$2"
    
    if [ $exit_code -eq 0 ]; then
        # Package found
        if [[ "$requirement_type" == "negative" ]]; then
            # For negative requirements, package found is bad
            echo "FAIL"
        else
            # For positive requirements, package found is good
            echo "PASS"
        fi
    else
        # Package not found
        if [[ "$requirement_type" == "negative" ]]; then
            # For negative requirements, package not found is good
            echo "PASS"
        else
            # For positive requirements, package not found is bad
            echo "FAIL"
        fi
    fi
}

# Function to evaluate systemctl command results
evaluate_systemctl_command() {
    local output="$1"
    local requirement_type="$2"
    local command="$3"
    
    if [[ "$command" == *"is-active"* ]]; then
        if [[ "$output" == *"active"* ]]; then
            # Service is active
            if [[ "$requirement_type" == "negative" ]]; then
                # For negative requirements, active is bad
                echo "FAIL"
            else
                # For positive requirements, active is good
                echo "PASS"
            fi
        else
            # Service is not active
            if [[ "$requirement_type" == "negative" ]]; then
                # For negative requirements, not active is good
                echo "PASS"
            else
                # For positive requirements, not active is bad
                echo "FAIL"
            fi
        fi
    elif [[ "$command" == *"is-enabled"* ]]; then
        if [[ "$output" == *"enabled"* ]]; then
            # Service is enabled
            if [[ "$requirement_type" == "negative" ]]; then
                # For negative requirements, enabled is bad
                echo "FAIL"
            else
                # For positive requirements, enabled is good
                echo "PASS"
            fi
        else
            # Service is not enabled
            if [[ "$requirement_type" == "negative" ]]; then
                # For negative requirements, not enabled is good
                echo "PASS"
            else
                # For positive requirements, not enabled is bad
                echo "FAIL"
            fi
        fi
    else
        # Unknown systemctl command
        if [ $exit_code -eq 0 ]; then
            echo "PASS"
        else
            echo "FAIL"
        fi
    fi
}

# Function to evaluate sysctl command results
evaluate_sysctl_command() {
    local output="$1"
    local requirement_type="$2"
    local command="$3"
    
    # Special case for TCP syncookies check
    if [[ "$command" == *"net.ipv4.tcp_syncookies"* ]] && [[ "$output" == *"= 1"* ]]; then
        if [[ "$requirement_type" == "negative" ]]; then
            echo "FAIL"
        else
            echo "PASS"
        fi
        return
    fi
    
    # Special case for kernel.dmesg_restrict check
    if [[ "$command" == *"kernel.dmesg_restrict"* ]] && [[ "$output" == *"= 1"* ]]; then
        if [[ "$requirement_type" == "negative" ]]; then
            echo "FAIL"
        else
            echo "PASS"
        fi
        return
    fi
    
    if [[ "$command" == *"net.ipv4.conf.all.send_redirects"* || 
          "$command" == *"net.ipv4.conf.default.send_redirects"* ||
          "$command" == *"net.ipv4.ip_forward"* ]]; then
        # These should be 0 for security
        if [[ "$output" == *"= 0"* ]]; then
            if [[ "$requirement_type" == "negative" ]]; then
                echo "FAIL"
            else
                echo "PASS"
            fi
        else
            if [[ "$requirement_type" == "negative" ]]; then
                echo "PASS"
            else
                echo "FAIL"
            fi
        fi
    fi
}

# Function to evaluate SSH ciphers configuration
evaluate_ssh_ciphers() {
    local exit_code="$1"
    local output="$2"
    
    if [ $exit_code -eq 0 ]; then
        # Check if the output contains the exact required ciphers
        if [[ "$output" == *"Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr"* ]]; then
            # Check if there are no commented out cipher lines
            if ! echo "$output" | grep -q "^#.*Ciphers"; then
                # Check if there are no other cipher configurations
                cipher_count=$(echo "$output" | grep -v "^#" | grep -c "Ciphers")
                if [ "$cipher_count" -eq 1 ]; then
                    echo "PASS"
                else
                    echo -e "${YELLOW}Multiple conflicting cipher configurations found${NC}" >&2
                    echo "FAIL"
                fi
            else
                echo -e "${YELLOW}Commented out cipher configuration found${NC}" >&2
                echo "FAIL"
            fi
        else
            echo -e "${YELLOW}Incorrect cipher configuration. Required: aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr${NC}" >&2
            echo "FAIL"
        fi
    else
        echo -e "${YELLOW}No cipher configuration found${NC}" >&2
        echo "FAIL"
    fi
}

# Function to evaluate INACTIVE setting in useradd configuration
evaluate_inactive_setting() {
    local exit_code="$1"
    local output="$2"
    
    if [ $exit_code -eq 0 ]; then
        # Check if the output is commented out
        if echo "$output" | grep -q "^#.*INACTIVE"; then
            echo -e "${YELLOW}INACTIVE setting is commented out${NC}" >&2
            echo "FAIL"
        else
            # Extract the INACTIVE value
            inactive_value=$(echo "$output" | grep -o "INACTIVE=[0-9-]*" | cut -d= -f2)
            # Check if the value is in the required range (0 < value <= 35)
            if [[ "$inactive_value" =~ ^[0-9]+$ ]] && [ "$inactive_value" -gt 0 ] && [ "$inactive_value" -le 35 ]; then
                echo "PASS"
            else
                echo -e "${YELLOW}INACTIVE value must be between 1 and 35, found: $inactive_value${NC}" >&2
                echo "FAIL"
            fi
        fi
    else
        echo -e "${YELLOW}INACTIVE setting not found${NC}" >&2
        echo "FAIL"
    fi
}

# Function to evaluate PASS_MAX_DAYS setting in login.defs
evaluate_pass_max_days() {
    local exit_code="$1"
    local output="$2"
    
    if [ $exit_code -eq 0 ]; then
        # Extract the value
        if [ -z "$output" ]; then
            echo -e "${YELLOW}PASS_MAX_DAYS parameter not found or is commented out${NC}" >&2
            echo "FAIL"
        else
            pass_max_days=$(echo "$output" | awk '{print $2}')
            # Check if the value is a number
            if [[ "$pass_max_days" =~ ^[0-9]+$ ]]; then
                # Check if the value is greater than 60
                if [ "$pass_max_days" -gt 60 ]; then
                    echo -e "${YELLOW}PASS_MAX_DAYS value ($pass_max_days) is greater than the required maximum of 60 days${NC}" >&2
                    echo "FAIL"
                else
                    echo "PASS"
                fi
            else
                echo -e "${YELLOW}PASS_MAX_DAYS value is not a valid number${NC}" >&2
                echo "FAIL"
            fi
        fi
    else
        echo -e "${YELLOW}PASS_MAX_DAYS parameter not found${NC}" >&2
        echo "FAIL"
    fi
}

# Function to evaluate command result based on command type
evaluate_command_result() {
    local exit_code="$1"
    local output="$2"
    local requirement_type="$3"
    local command="$4"
    local rule_id="$5"
    
    if [[ "$command" == *"grep -r 'Ciphers' /etc/ssh/sshd_config"* || "$command" == *"grep -r 'Ciphers' /etc/ssh/ssh_config"* ]]; then
        evaluate_ssh_ciphers "$exit_code" "$output"
    elif [[ "$command" == *"grep INACTIVE /etc/default/useradd"* ]]; then
        evaluate_inactive_setting "$exit_code" "$output"
    elif [[ "$command" == *"grep -i ^PASS_MAX_DAYS /etc/login.defs"* ]]; then
        evaluate_pass_max_days "$exit_code" "$output"
    elif [[ "$command" == *"ls /etc/cron.weekly"* ]]; then
        if [[ "$output" == *"audit-offload"* ]]; then
            echo "PASS"
        else
            echo -e "${YELLOW}Required audit-offload script not found in /etc/cron.weekly${NC}" >&2
            echo "FAIL"
        fi
    elif [[ "$command" == *"grep"* && "$command" == *"sysctl"* ]]; then
        # Special handling for sysctl grep commands
        if [ $exit_code -eq 2 ] && [[ "$output" != "" ]]; then
            # If we got output but exit code 2, this is likely a pattern match issue
            # Extract the sysctl parameter name from the command
            param_name=$(echo "$command" | grep -o '[a-z0-9._]*\\.[a-z0-9._]*' | head -1)
            if [[ -n "$param_name" ]]; then
                # Check if there's an uncommented setting with value 1
                if [[ "$output" == *"$param_name=1"* ]] || [[ "$output" == *"$param_name = 1"* ]]; then
                    if [[ "$requirement_type" == "negative" ]]; then
                        echo "FAIL"
                    else
                        echo "PASS"
                    fi
                # Check if there's an uncommented setting with value 0
                elif [[ "$output" == *"$param_name=0"* ]] || [[ "$output" == *"$param_name = 0"* ]]; then
                    if [[ "$requirement_type" == "negative" ]]; then
                        echo "PASS"
                    else
                        echo "FAIL"
                        echo -e "${YELLOW}$param_name is set to 0 in configuration files${NC}" >&2
                    fi
                # Check if there's only commented settings
                elif [[ "$output" == *"#$param_name"* ]]; then
                    if [[ "$requirement_type" == "negative" ]]; then
                        echo "PASS"
                    else
                        echo "FAIL"
                        echo -e "${YELLOW}$param_name setting is commented out in configuration files${NC}" >&2
                    fi
                else
                    # No settings found or couldn't determine
                    evaluate_grep_command "$exit_code" "$output" "$requirement_type" "$command"
                fi
            else
                # Couldn't extract parameter name, use standard grep evaluation
                evaluate_grep_command "$exit_code" "$output" "$requirement_type" "$command"
            fi
        else
            # Use standard grep evaluation for other cases
            evaluate_grep_command "$exit_code" "$output" "$requirement_type" "$command"
        fi
    # Special case for X11Forwarding check
    elif [[ "$command" == *"grep -ir x11forwarding /etc/ssh/sshd_config"* ]]; then
        # Check if there's an uncommented X11Forwarding line set to no
        if [[ "$output" == *"X11Forwarding no"* ]] && [[ ! "$output" == *"#X11Forwarding no"* ]]; then
            if [[ "$requirement_type" == "negative" ]]; then
                echo "FAIL"
            else
                echo "PASS"
            fi
        elif [[ "$output" == *"X11Forwarding yes"* ]] && [[ ! "$output" == *"#X11Forwarding yes"* ]]; then
            if [[ "$requirement_type" == "negative" ]]; then
                echo "PASS"
            else
                echo "FAIL"
                echo -e "${YELLOW}X11Forwarding is enabled${NC}" >&2
            fi
        else
            # No uncommented X11Forwarding setting found
            if [[ "$requirement_type" == "negative" ]]; then
                echo "PASS"
            else
                echo "FAIL"
                echo -e "${YELLOW}X11Forwarding setting not found or is commented out${NC}" >&2
            fi
        fi
    # Special case for SSH banner acknowledgement check
    elif [[ "$command" == *"less /etc/profile.d/ssh_confirm.sh"* ]] || ([[ "$command" == *"cat /etc/profile.d/ssh_confirm.sh"* ]]); then
        if [ $exit_code -ne 0 ] || [[ "$output" == *"No such file or directory"* ]]; then
            echo "FAIL"
            echo -e "${YELLOW}SSH banner acknowledgement script not found${NC}" >&2
        elif [[ "$output" != *"You are accessing a U.S. Government (USG) Information System"* ]] || \
             [[ "$output" != *"Do you agree? [y/N]"* ]]; then
            echo "FAIL"
            echo -e "${YELLOW}SSH banner acknowledgement script does not contain the required content${NC}" >&2
        else
            echo "PASS"
        fi
    # Special case for SSH banner content check
    elif [[ "$command" == *"cat /etc/issue.net"* ]] && [[ "$rule_id" == *"SV-270691"* ]]; then
        # Check if the banner content matches the DoD banner
        if [[ "$output" == *"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only"* ]] && \
           [[ "$output" == *"By using this IS (which includes any device attached to this IS), you consent to the following conditions"* ]] && \
           [[ "$output" == *"-The USG routinely intercepts and monitors communications on this IS"* ]] && \
           [[ "$output" == *"-At any time, the USG may inspect and seize data stored on this IS"* ]] && \
           [[ "$output" == *"-Communications using, or data stored on, this IS are not private"* ]] && \
           [[ "$output" == *"-This IS includes security measures"* ]] && \
           [[ "$output" == *"-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching"* ]]; then
            echo "PASS"
        else
            echo "FAIL"
            echo -e "${YELLOW}SSH banner content does not match the required DoD Notice and Consent Banner${NC}" >&2
        fi
    # Special case for FIPS mode check
    elif [[ "$command" == *"grep -i 1 /proc/sys/crypto/fips_enabled"* ]] && [[ "$rule_id" == *"SV-270744"* ]]; then
        # Check if the file doesn't exist
        if [[ "$output" == *"No such file or directory"* ]]; then
            echo "FAIL"
            echo -e "${YELLOW}FIPS mode is not enabled - /proc/sys/crypto/fips_enabled file not found${NC}" >&2
        # Check if the file exists but doesn't contain "1"
        elif [ $exit_code -ne 0 ]; then
            echo "FAIL"
            echo -e "${YELLOW}FIPS mode is not enabled - value is not set to 1${NC}" >&2
        else
            echo "PASS"
        fi
    elif [[ "$command" == *"grep"* ]]; then
        evaluate_grep_command "$exit_code" "$output" "$requirement_type" "$command"
    elif [[ "$command" == *"dpkg -l"* || "$command" == *"apt list"* ]]; then
        evaluate_package_check "$exit_code" "$requirement_type"
    elif [[ "$command" == *"systemctl"* ]]; then
        evaluate_systemctl_command "$output" "$requirement_type" "$command"
    elif [[ "$command" == *"sysctl"* ]]; then
        evaluate_sysctl_command "$output" "$requirement_type" "$command"
    else
        # Default evaluation based on exit code
        if [ $exit_code -eq 0 ]; then
            echo "PASS"
        else
            echo "FAIL"
        fi
    fi
}

# Function to check if a check is manual based on content
is_manual_check() {
    local check_content="$1"
    
    if [[ "$check_content" == *"interview"* || 
          "$check_content" == *"ask the"* || 
          "$check_content" == *"manual"* || 
          "$check_content" == *"documented"* ]]; then
        echo "true"
    else
        echo "false"
    fi
}

# Print header
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}       Ubuntu STIG Compliance Checker                  ${NC}"
echo -e "${CYAN}=======================================================${NC}"
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}This script must be run as root${NC}"
    exit 1
fi

echo -e "${BLUE}Starting compliance checks...${NC}"
echo ""

"""

def generate_check_block(rule_id, title, check_content, commands, requirement_type, check_type):
    """Generate a block for a single STIG check."""
    block = f"""
# {'-' * 80}
# Check for {rule_id}: {title}
# {'-' * 80}
echo -e "\\n${{CYAN}}=== Checking {rule_id} ===${{NC}}"
echo -e "${{BLUE}}Title:${{NC}} {title}"
echo -e "${{BLUE}}Requirement Type:${{NC}} {requirement_type}"
echo -e "${{BLUE}}Check Type:${{NC}} {check_type}\\n"

# Check Content:
cat << 'EOF'
{check_content}
EOF

echo ""

"""
    
    # If no commands, mark as manual check
    if not commands:
        block += f"""
echo -e "${{YELLOW}}[MANUAL]${{NC}} No automated commands available for this check."
result="MANUAL"
update_counters "$result"
echo -e "${{YELLOW}}[MANUAL]${{NC}} {rule_id}: {title}"
"""
    else:
        # Add command execution for each command
        block += """
# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass
"""
        
        for i, cmd in enumerate(commands):
            # Fix any problematic commands
            cmd = fix_command(cmd, rule_id)
            
            # Standard approach for other commands
            cmd_escaped = cmd.replace('"', '\\"').replace('$', '\\$')
            
            block += f"""
# Command {i+1}
echo -e "${{BLUE}}Executing:${{NC}} {cmd_escaped}"
output_{i}=$(eval "{cmd_escaped}" 2>&1)
exit_code_{i}=$?
echo -e "${{BLUE}}Exit Code:${{NC}} $exit_code_{i}"
echo -e "${{BLUE}}Output:${{NC}}"
echo "$output_{i}"
echo ""

# Evaluate command result using function
cmd_result_{i}=$(evaluate_command_result "$exit_code_{i}" "$output_{i}" "{requirement_type}" "{cmd_escaped}" "{rule_id}")
echo -e "${{BLUE}}Command {i+1} Result:${{NC}} $cmd_result_{i}"

# If any command fails, the whole rule fails
if [ "$cmd_result_{i}" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_{i}" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_{i}" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi

"""
        
        # Check if this is a manual check based on content
        block += f"""
# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${{YELLOW}}This appears to be a manual check based on content.${{NC}}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "{rule_id}" "{title}"

update_counters "$rule_result"
"""
    
    return block

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

# Calculate compliance percentage (excluding manual and not checked)
if [ $((PASSED + FAILED)) -gt 0 ]; then
    COMPLIANCE_PERCENT=$(( (PASSED * 100) / (PASSED + FAILED) ))
    echo -e "${BLUE}Compliance Percentage:${NC} ${COMPLIANCE_PERCENT}%"
else
    echo -e "${BLUE}Compliance Percentage:${NC} N/A (no automated checks)"
fi

echo -e "${CYAN}=======================================================${NC}"
"""

if __name__ == "__main__":
    main()
