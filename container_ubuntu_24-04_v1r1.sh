#!/bin/bash
# Ubuntu STIG Compliance Checker
# Auto-generated script to check STIG compliance

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
            param_name=$(echo "$command" | grep -o '[a-z0-9._]*\.[a-z0-9._]*' | head -1)
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
        elif [[ "$output" != *"You are accessing a U.S. Government (USG) Information System"* ]] ||              [[ "$output" != *"Do you agree? [y/N]"* ]]; then
            echo "FAIL"
            echo -e "${YELLOW}SSH banner acknowledgement script does not contain the required content${NC}" >&2
        else
            echo "PASS"
        fi
    # Special case for SSH banner content check
    elif [[ "$command" == *"cat /etc/issue.net"* ]] && [[ "$rule_id" == *"SV-270691"* ]]; then
        # Check if the banner content matches the DoD banner
        if [[ "$output" == *"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only"* ]] &&            [[ "$output" == *"By using this IS (which includes any device attached to this IS), you consent to the following conditions"* ]] &&            [[ "$output" == *"-The USG routinely intercepts and monitors communications on this IS"* ]] &&            [[ "$output" == *"-At any time, the USG may inspect and seize data stored on this IS"* ]] &&            [[ "$output" == *"-Communications using, or data stored on, this IS are not private"* ]] &&            [[ "$output" == *"-This IS includes security measures"* ]] &&            [[ "$output" == *"-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching"* ]]; then
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


# --------------------------------------------------------------------------------
# Check for SV-270646r1068358_rule: Ubuntu 24.04 LTS must not have the "ntp" package installed.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270646r1068358_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must not have the "ntp" package installed."
echo -e "${BLUE}Requirement Type:${NC} negative"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify the "ntp" package is not installed with the following command:

$ dpkg -l | grep ntp

If the "ntp" package is installed, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} dpkg -l | grep ntp"
output_0=$(eval "dpkg -l | grep ntp" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "negative" "dpkg -l | grep ntp" "SV-270646r1068358_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270646r1068358_rule" "Ubuntu 24.04 LTS must not have the "ntp" package installed."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270647r1066430_rule: Ubuntu 24.04 LTS must not have the telnet package installed.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270647r1066430_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must not have the telnet package installed."
echo -e "${BLUE}Requirement Type:${NC} negative"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify the telnet package is not installed on Ubuntu 24.04 LTS with the following command: 
 
$ dpkg -l | grep telnetd 

If the telnetd package is installed, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} dpkg -l | grep telnetd"
output_0=$(eval "dpkg -l | grep telnetd" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "negative" "dpkg -l | grep telnetd" "SV-270647r1066430_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270647r1066430_rule" "Ubuntu 24.04 LTS must not have the telnet package installed."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270648r1066433_rule: Ubuntu 24.04 LTS must not have the rsh-server package installed.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270648r1066433_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must not have the rsh-server package installed."
echo -e "${BLUE}Requirement Type:${NC} negative"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify the rsh-server package is installed with the following command: 
 
$ dpkg -l | grep rsh-server 
 
If the rsh-server package is installed, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} dpkg -l | grep rsh-server"
output_0=$(eval "dpkg -l | grep rsh-server" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "negative" "dpkg -l | grep rsh-server" "SV-270648r1066433_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270648r1066433_rule" "Ubuntu 24.04 LTS must not have the rsh-server package installed."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270674r1067167_rule: Ubuntu 24.04 LTS must allow users to directly initiate a session lock for all connection types.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270674r1067167_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must allow users to directly initiate a session lock for all connection types."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 24.04 LTS has the "vlock" package installed with the following command: 
 
$ dpkg -l | grep vlock 
ii  vlock     2.2.2-10     amd64     Virtual Console locking program
 
If "vlock" is not installed, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} dpkg -l | grep vlock"
output_0=$(eval "dpkg -l | grep vlock" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "dpkg -l | grep vlock" "SV-270674r1067167_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270674r1067167_rule" "Ubuntu 24.04 LTS must allow users to directly initiate a session lock for all connection types."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270677r1066520_rule: Ubuntu 24.04 LTS must limit the number of concurrent sessions to 10 for all accounts and/or account types.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270677r1066520_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must limit the number of concurrent sessions to 10 for all accounts and/or account types."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 24.04 LTS limits the number of concurrent sessions to 10 for all accounts and/or account types with the following command: 
 
$ grep maxlogins /etc/security/limits.conf | grep -v '^* hard maxlogins' 
* hard maxlogins 10 
 
If the "maxlogins" item does not have a value of "10" or less, is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep maxlogins /etc/security/limits.conf | grep -v '^* hard maxlogins'"
output_0=$(eval "grep maxlogins /etc/security/limits.conf | grep -v '^* hard maxlogins'" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep maxlogins /etc/security/limits.conf | grep -v '^* hard maxlogins'" "SV-270677r1066520_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270677r1066520_rule" "Ubuntu 24.04 LTS must limit the number of concurrent sessions to 10 for all accounts and/or account types."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270680r1066529_rule: Ubuntu 24.04 LTS must automatically terminate a user session after inactivity timeouts have expired.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270680r1066529_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must automatically terminate a user session after inactivity timeouts have expired."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 24.04 LTS automatically terminates a user session after inactivity timeouts have expired with the following command:
 
$ sudo grep -E "\bTMOUT=[0-9]+" /etc/bash.bashrc /etc/profile.d/*
/etc/profile.d/99-terminal_tmout.sh:TMOUT=600 

If "TMOUT" is not set, or if the value is "0" or is commented out, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -E \"\bTMOUT=[0-9]+\" /etc/bash.bashrc /etc/profile.d/*"
output_0=$(eval "grep -E \"\bTMOUT=[0-9]+\" /etc/bash.bashrc /etc/profile.d/*" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -E \"\bTMOUT=[0-9]+\" /etc/bash.bashrc /etc/profile.d/*" "SV-270680r1066529_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270680r1066529_rule" "Ubuntu 24.04 LTS must automatically terminate a user session after inactivity timeouts have expired."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270682r1066535_rule: Ubuntu 24.04 LTS must automatically remove or disable emergency accounts after 72 hours.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270682r1066535_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must automatically remove or disable emergency accounts after 72 hours."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify temporary accounts have been provisioned with an expiration date of 72 hours with the following command:

$ sudo chage -l  | grep -i "account expires"

Verify each of these accounts has an expiration date set within 72 hours.

If any temporary accounts have no expiration date set or do not expire within 72 hours, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} chage -l  | grep -i \"account expires\""
output_0=$(eval "chage -l  | grep -i \"account expires\"" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "chage -l  | grep -i \"account expires\"" "SV-270682r1066535_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270682r1066535_rule" "Ubuntu 24.04 LTS must automatically remove or disable emergency accounts after 72 hours."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270683r1066538_rule: Ubuntu 24.04 LTS must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270683r1066538_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the account identifiers (individuals, groups, roles, and devices) are disabled after 35 days of inactivity with the following command: 
 
Check the account inactivity value by performing the following command: 
 
$ grep INACTIVE /etc/default/useradd
INACTIVE=35 
 
If "INACTIVE" is not set to a value 0<[VALUE]<=35, is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep INACTIVE /etc/default/useradd"
output_0=$(eval "grep INACTIVE /etc/default/useradd" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep INACTIVE /etc/default/useradd" "SV-270683r1066538_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270683r1066538_rule" "Ubuntu 24.04 LTS must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270696r1066577_rule: Ubuntu 24.04 LTS library files must have mode 0755 or less permissive.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270696r1066577_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS library files must have mode 0755 or less permissive."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the systemwide shared library files contained in the directories "/lib", "/lib64", and "/usr/lib" have mode 0755 or less permissive with the following command: 
 
$ sudo find /lib /lib64 /usr/lib -perm /022 -type f -exec stat -c "%n %a" '{}' \; 

If any files are found to be group-writable or world-writable, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /lib /lib64 /usr/lib -perm /022 -type f -exec stat -c \"%n %a\" '{}' \;"
output_0=$(eval "find /lib /lib64 /usr/lib -perm /022 -type f -exec stat -c \"%n %a\" '{}' \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /lib /lib64 /usr/lib -perm /022 -type f -exec stat -c \"%n %a\" '{}' \;" "SV-270696r1066577_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270696r1066577_rule" "Ubuntu 24.04 LTS library files must have mode 0755 or less permissive."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270697r1066580_rule: Ubuntu 24.04 LTS library files must be owned by root.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270697r1066580_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS library files must be owned by root."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the systemwide shared library files contained in the directories "/lib", "/lib64", and "/usr/lib" are owned by root with the following command: 
 
$ sudo find /lib /usr/lib /lib64 ! -user root -type f -exec stat -c "%n %U" '{}' \; 
 
If any systemwide library file is returned, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /lib /usr/lib /lib64 ! -user root -type f -exec stat -c \"%n %U\" '{}' \;"
output_0=$(eval "find /lib /usr/lib /lib64 ! -user root -type f -exec stat -c \"%n %U\" '{}' \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /lib /usr/lib /lib64 ! -user root -type f -exec stat -c \"%n %U\" '{}' \;" "SV-270697r1066580_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270697r1066580_rule" "Ubuntu 24.04 LTS library files must be owned by root."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270698r1066583_rule: Ubuntu 24.04 LTS library directories must be owned by root.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270698r1066583_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS library directories must be owned by root."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the systemwide shared library directories "/lib", "/lib64", and "/usr/lib" are owned by root with the following command: 
 
$ sudo find /lib /usr/lib /lib64 ! -user root -type d -exec stat -c "%n %U" '{}' \; 
 
If any systemwide library directory is returned, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /lib /usr/lib /lib64 ! -user root -type d -exec stat -c \"%n %U\" '{}' \;"
output_0=$(eval "find /lib /usr/lib /lib64 ! -user root -type d -exec stat -c \"%n %U\" '{}' \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /lib /usr/lib /lib64 ! -user root -type d -exec stat -c \"%n %U\" '{}' \;" "SV-270698r1066583_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270698r1066583_rule" "Ubuntu 24.04 LTS library directories must be owned by root."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270699r1066586_rule: Ubuntu 24.04 LTS library files must be group-owned by root or a system account.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270699r1066586_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS library files must be group-owned by root or a system account."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the systemwide library files contained in the directories "/lib", "/lib64", and "/usr/lib" are group-owned by root, or a required system account, with the following command: 
 
$ sudo find /lib /usr/lib /lib64 ! -group root -type f -exec stat -c "%n %G" '{}' \; 
 
If any systemwide shared library file is returned and is not group-owned by a required system account, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /lib /usr/lib /lib64 ! -group root -type f -exec stat -c \"%n %G\" '{}' \;"
output_0=$(eval "find /lib /usr/lib /lib64 ! -group root -type f -exec stat -c \"%n %G\" '{}' \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /lib /usr/lib /lib64 ! -group root -type f -exec stat -c \"%n %G\" '{}' \;" "SV-270699r1066586_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270699r1066586_rule" "Ubuntu 24.04 LTS library files must be group-owned by root or a system account."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270700r1066589_rule: Ubuntu 24.04 LTS library directories must be group-owned by root.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270700r1066589_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS library directories must be group-owned by root."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the systemwide library directories "/lib", "/lib64", and "/usr/lib" are group-owned by root with the following command: 
 
$ sudo find /lib /usr/lib /lib64 ! -group root -type d -exec stat -c "%n %G" '{}' \; 
 
If any systemwide shared library directory is returned, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /lib /usr/lib /lib64 ! -group root -type d -exec stat -c \"%n %G\" '{}' \;"
output_0=$(eval "find /lib /usr/lib /lib64 ! -group root -type d -exec stat -c \"%n %G\" '{}' \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /lib /usr/lib /lib64 ! -group root -type d -exec stat -c \"%n %G\" '{}' \;" "SV-270700r1066589_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270700r1066589_rule" "Ubuntu 24.04 LTS library directories must be group-owned by root."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270701r1066592_rule: Ubuntu 24.04 LTS must have system commands set to a mode of 0755 or less permissive.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270701r1066592_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must have system commands set to a mode of 0755 or less permissive."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the system commands contained in the following directories have mode 0755 or less permissive with the following command: 
 
$ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c "%n %a" '{}' \; 
 
If any files are found to be group-writable or world-writable, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c \"%n %a\" '{}' \;"
output_0=$(eval "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c \"%n %a\" '{}' \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c \"%n %a\" '{}' \;" "SV-270701r1066592_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270701r1066592_rule" "Ubuntu 24.04 LTS must have system commands set to a mode of 0755 or less permissive."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270702r1066595_rule: Ubuntu 24.04 LTS must have system commands owned by root or a system account.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270702r1066595_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must have system commands owned by root or a system account."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the system commands contained in the following directories are owned by root, or a required system account, with the following command: 
 
$ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c "%n %U" '{}' \; 
 
If any system commands are returned and not owned by a required system account, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c \"%n %U\" '{}' \;"
output_0=$(eval "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c \"%n %U\" '{}' \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c \"%n %U\" '{}' \;" "SV-270702r1066595_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270702r1066595_rule" "Ubuntu 24.04 LTS must have system commands owned by root or a system account."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270703r1066598_rule: Ubuntu 24.04 LTS must have system commands group-owned by root or a system account.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270703r1066598_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must have system commands group-owned by root or a system account."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the system commands contained in the following directories are group-owned by root or a required system account with the following command: 
 
$ find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin \-type f -perm -u=x -exec stat --format="%n %G" {} + |  \awk '$2 != "root" && $2 != "daemon" && $2 != "adm" && $2 != "shadow" && $2 != "mail" && $2 != "crontab" && $2 != "_ssh"'

Note: The above command uses awk to filter out common system accounts. If your system uses other required system accounts, add them to the awk condition to filter them out of the results.

If any system commands are returned that are not group-owned by a required system account, this is a finding.
EOF

echo ""


echo -e "${YELLOW}[MANUAL]${NC} No automated commands available for this check."
result="MANUAL"
update_counters "$result"
echo -e "${YELLOW}[MANUAL]${NC} SV-270703r1066598_rule: Ubuntu 24.04 LTS must have system commands group-owned by root or a system account."

# --------------------------------------------------------------------------------
# Check for SV-270704r1066601_rule: Ubuntu 24.04 LTS must prevent the use of dictionary words for passwords.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270704r1066601_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must prevent the use of dictionary words for passwords."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 24.04 LTS uses the "cracklib" library to prevent the use of dictionary words with the following command: 
 
$ grep dictcheck /etc/security/pwquality.conf
dictcheck=1 
 
If the "dictcheck" parameter is not set to "1" or is commented out, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep dictcheck /etc/security/pwquality.conf"
output_0=$(eval "grep dictcheck /etc/security/pwquality.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep dictcheck /etc/security/pwquality.conf" "SV-270704r1066601_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270704r1066601_rule" "Ubuntu 24.04 LTS must prevent the use of dictionary words for passwords."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270707r1066610_rule: Ubuntu 24.04 LTS must require users to reauthenticate for privilege escalation or when changing roles.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270707r1066610_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must require users to reauthenticate for privilege escalation or when changing roles."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify the "/etc/sudoers" file has no occurrences of "NOPASSWD" or "!authenticate" with the following command: 
 
$ sudo egrep -i '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/* 
 
If any occurrences of "NOPASSWD" or "!authenticate" return from the command, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} egrep -i '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*"
output_0=$(eval "egrep -i '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "egrep -i '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*" "SV-270707r1066610_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270707r1066610_rule" "Ubuntu 24.04 LTS must require users to reauthenticate for privilege escalation or when changing roles."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270713r1066628_rule: Ubuntu 24.04 LTS must not have accounts configured with blank or null passwords.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270713r1066628_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must not have accounts configured with blank or null passwords."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Check the "/etc/shadow" file for blank passwords with the following command:

$ sudo awk -F: '!$2 {print $1}' /etc/shadow

If the command returns any results, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} awk -F: '!\$2 {print \$1}' /etc/shadow"
output_0=$(eval "awk -F: '!\$2 {print \$1}' /etc/shadow" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "awk -F: '!\$2 {print \$1}' /etc/shadow" "SV-270713r1066628_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270713r1066628_rule" "Ubuntu 24.04 LTS must not have accounts configured with blank or null passwords."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270720r1066649_rule: Ubuntu 24.04 LTS must uniquely identify interactive users.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270720r1066649_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must uniquely identify interactive users."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 24.04 LTS contains no duplicate User IDs (UIDs) for interactive users with the following command: 
 
$ awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd 
 
If output is produced and the accounts listed are interactive user accounts, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} awk -F \":\" 'list[\$3]++{print \$1, \$3}' /etc/passwd"
output_0=$(eval "awk -F \":\" 'list[\$3]++{print \$1, \$3}' /etc/passwd" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "awk -F \":\" 'list[\$3]++{print \$1, \$3}' /etc/passwd" "SV-270720r1066649_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270720r1066649_rule" "Ubuntu 24.04 LTS must uniquely identify interactive users."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270724r1066661_rule: Ubuntu 24.04 LTS must prevent direct login to the root account.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270724r1066661_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must prevent direct login to the root account."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 24.04 LTS prevents direct logins to the root account with the following command: 
 
$ sudo passwd -S root
root L 04/08/2024 0 99999 7 -1 
 
If the output does not contain "L" in the second field to indicate the account is locked, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} passwd -S root"
output_0=$(eval "passwd -S root" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "passwd -S root" "SV-270724r1066661_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270724r1066661_rule" "Ubuntu 24.04 LTS must prevent direct login to the root account."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270726r1066667_rule: Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one uppercase character be used.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270726r1066667_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one uppercase character be used."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 24.04 LTS enforces password complexity by requiring that at least one uppercase character be used with the following command: 
 
$ grep -i "ucredit" /etc/security/pwquality.conf
ucredit=-1 
 
If the "ucredit" parameter is greater than "-1", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i \"ucredit\" /etc/security/pwquality.conf"
output_0=$(eval "grep -i \"ucredit\" /etc/security/pwquality.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i \"ucredit\" /etc/security/pwquality.conf" "SV-270726r1066667_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270726r1066667_rule" "Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one uppercase character be used."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270727r1066670_rule: Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one lowercase character be used.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270727r1066670_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one lowercase character be used."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 24.04 LTS enforces password complexity by requiring that at least one lowercase character be used with the following command: 
 
$ grep -i "lcredit" /etc/security/pwquality.conf
lcredit=-1 
 
If the "lcredit" parameter is greater than "-1", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i \"lcredit\" /etc/security/pwquality.conf"
output_0=$(eval "grep -i \"lcredit\" /etc/security/pwquality.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i \"lcredit\" /etc/security/pwquality.conf" "SV-270727r1066670_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270727r1066670_rule" "Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one lowercase character be used."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270728r1066673_rule: Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one numeric character be used.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270728r1066673_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one numeric character be used."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 24.04 LTS enforces password complexity by requiring that at least one numeric character be used. 
 
Determine if the field "dcredit" is set in the "/etc/security/pwquality.conf" file with the following command: 
 
$ grep -i "dcredit" /etc/security/pwquality.conf
dcredit=-1 
 
If the "dcredit" parameter is greater than "-1", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i \"dcredit\" /etc/security/pwquality.conf"
output_0=$(eval "grep -i \"dcredit\" /etc/security/pwquality.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i \"dcredit\" /etc/security/pwquality.conf" "SV-270728r1066673_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270728r1066673_rule" "Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one numeric character be used."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270729r1066676_rule: Ubuntu 24.04 LTS must require the change of at least eight characters when passwords are changed.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270729r1066676_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must require the change of at least eight characters when passwords are changed."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 24.04 LTS requires the change of at least eight characters when passwords are changed with the following command:
 
$ grep -i "difok" /etc/security/pwquality.conf
difok=8 
 
If the "difok" parameter is less than "8" or is commented out, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i \"difok\" /etc/security/pwquality.conf"
output_0=$(eval "grep -i \"difok\" /etc/security/pwquality.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i \"difok\" /etc/security/pwquality.conf" "SV-270729r1066676_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270729r1066676_rule" "Ubuntu 24.04 LTS must require the change of at least eight characters when passwords are changed."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270730r1066679_rule: Ubuntu 24.04 LTS must enforce 24 hours/1 day as the minimum password lifetime. Passwords for new users must have a 24 hours/1 day minimum password lifetime restriction.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270730r1066679_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must enforce 24 hours/1 day as the minimum password lifetime. Passwords for new users must have a 24 hours/1 day minimum password lifetime restriction."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 24.04 LTS enforces a 24 hours/1 day minimum password lifetime for new user accounts with the following command: 
 
$ grep -i ^PASS_MIN_DAYS /etc/login.defs 
PASS_MIN_DAYS    1 
 
If the "PASS_MIN_DAYS" parameter value is less than "1" or is commented out, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i ^PASS_MIN_DAYS /etc/login.defs"
output_0=$(eval "grep -i ^PASS_MIN_DAYS /etc/login.defs" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i ^PASS_MIN_DAYS /etc/login.defs" "SV-270730r1066679_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270730r1066679_rule" "Ubuntu 24.04 LTS must enforce 24 hours/1 day as the minimum password lifetime. Passwords for new users must have a 24 hours/1 day minimum password lifetime restriction."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270731r1066682_rule: Ubuntu 24.04 LTS must enforce a 60-day maximum password lifetime restriction. Passwords for new users must have a 60-day maximum password lifetime restriction.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270731r1066682_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must enforce a 60-day maximum password lifetime restriction. Passwords for new users must have a 60-day maximum password lifetime restriction."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 24.04 LTS enforces a 60-day maximum password lifetime for new user accounts with the following command:
 
$ grep -i ^PASS_MAX_DAYS /etc/login.defs
PASS_MAX_DAYS    60 
 
If the "PASS_MAX_DAYS" parameter value is less than "60" or is commented out, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i ^PASS_MAX_DAYS /etc/login.defs"
output_0=$(eval "grep -i ^PASS_MAX_DAYS /etc/login.defs" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i ^PASS_MAX_DAYS /etc/login.defs" "SV-270731r1066682_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270731r1066682_rule" "Ubuntu 24.04 LTS must enforce a 60-day maximum password lifetime restriction. Passwords for new users must have a 60-day maximum password lifetime restriction."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270732r1066685_rule: Ubuntu 24.04 LTS must enforce a minimum 15-character password length.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270732r1066685_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must enforce a minimum 15-character password length."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify the pwquality configuration file enforces a minimum 15-character password length with the following command:

$ grep -i minlen /etc/security/pwquality.conf
minlen=15

If "minlen" parameter value is not "15" or higher, is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i minlen /etc/security/pwquality.conf"
output_0=$(eval "grep -i minlen /etc/security/pwquality.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i minlen /etc/security/pwquality.conf" "SV-270732r1066685_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270732r1066685_rule" "Ubuntu 24.04 LTS must enforce a minimum 15-character password length."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270733r1066688_rule: Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one special character be used.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270733r1066688_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one special character be used."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Determine if the field "ocredit" is set in the "/etc/security/pwquality.conf" file with the following command: 
 
$ grep -i "ocredit" /etc/security/pwquality.conf
ocredit=-1 
 
If the "ocredit" parameter is greater than "-1", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i \"ocredit\" /etc/security/pwquality.conf"
output_0=$(eval "grep -i \"ocredit\" /etc/security/pwquality.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i \"ocredit\" /etc/security/pwquality.conf" "SV-270733r1066688_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270733r1066688_rule" "Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one special character be used."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270748r1066733_rule: Ubuntu 24.04 LTS must ensure only users who need access to security functions are part of sudo group.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270748r1066733_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must ensure only users who need access to security functions are part of sudo group."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the sudo group has only members who require access to security functions with the following command:  
 
$ grep sudo /etc/group
sudo:x:27:foo 
 
If the sudo group contains users not needing access to security functions, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep sudo /etc/group"
output_0=$(eval "grep sudo /etc/group" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep sudo /etc/group" "SV-270748r1066733_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270748r1066733_rule" "Ubuntu 24.04 LTS must ensure only users who need access to security functions are part of sudo group."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270750r1066739_rule: Ubuntu 24.04 LTS must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270750r1066739_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify all public (world-writeable) directories have the public sticky bit set with the following command:  
 
$ sudo find / -type d -perm -002 ! -perm -1000 
 
If any world-writable directories are found missing the sticky bit, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find / -type d -perm -002 ! -perm -1000"
output_0=$(eval "find / -type d -perm -002 ! -perm -1000" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find / -type d -perm -002 ! -perm -1000" "SV-270750r1066739_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270750r1066739_rule" "Ubuntu 24.04 LTS must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270756r1066757_rule: Ubuntu 24.04 LTS must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270756r1066757_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 24.04 LTS has all system log files under the /var/log directory with a permission set to "640" or less permissive with the following command:

Note: The btmp, wtmp, and lastlog files are excluded. Refer to the Discussion for details.

$ sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c "%n %a" {} \;

If the command displays any output, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c \"%n %a\" {} \;"
output_0=$(eval "find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c \"%n %a\" {} \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c \"%n %a\" {} \;" "SV-270756r1066757_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270756r1066757_rule" "Ubuntu 24.04 LTS must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270757r1066760_rule: Ubuntu 24.04 LTS must generate system journal entries without revealing information that could be exploited by adversaries.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270757r1066760_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must generate system journal entries without revealing information that could be exploited by adversaries."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the /run/log/journal and /var/log/journal directories have permissions set to "2640" or less permissive with the following command:

$ sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %a" {} \;
/run/log/journal 2640
/var/log/journal 2640
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e 2640

If any output returned has a permission set greater than 2640, this is a finding.

Verify all files in the /run/log/journal and /var/log/journal directories have permissions set to "640" or less permissive with the following command:

$ sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %a" {} \;
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/system.journal 640
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/user-1000@0005f97cd4a8c9b5a.journal~ 640
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/system@0005f97cd2a1e0a7-d58b848af46813a4.journal~ 640
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/system@0005f97cb900e501-55ea053b7f75ae1c.journal~ 640
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/user-1000.journal 640

If any output returned has a permission set greater than "640", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /run/log/journal /var/log/journal  -type d -exec stat -c \"%n %a\" {} \;"
output_0=$(eval "find /run/log/journal /var/log/journal  -type d -exec stat -c \"%n %a\" {} \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /run/log/journal /var/log/journal  -type d -exec stat -c \"%n %a\" {} \;" "SV-270757r1066760_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Command 2
echo -e "${BLUE}Executing:${NC} find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %a\" {} \;"
output_1=$(eval "find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %a\" {} \;" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %a\" {} \;" "SV-270757r1066760_rule")
echo -e "${BLUE}Command 2 Result:${NC} $cmd_result_1"

# If any command fails, the whole rule fails
if [ "$cmd_result_1" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_1" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_1" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270757r1066760_rule" "Ubuntu 24.04 LTS must generate system journal entries without revealing information that could be exploited by adversaries."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270763r1066778_rule: Ubuntu 24.04 LTS must configure the directories used by the system journal to be owned by "root".
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270763r1066778_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must configure the directories used by the system journal to be owned by "root"."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the /run/log/journal and /var/log/journal directories are owned by "root" with the following command:

$ sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %U" {} \;
/run/log/journal root
/var/log/journal root
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e root

If any output returned is not owned by "root", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /run/log/journal /var/log/journal  -type d -exec stat -c \"%n %U\" {} \;"
output_0=$(eval "find /run/log/journal /var/log/journal  -type d -exec stat -c \"%n %U\" {} \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /run/log/journal /var/log/journal  -type d -exec stat -c \"%n %U\" {} \;" "SV-270763r1066778_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270763r1066778_rule" "Ubuntu 24.04 LTS must configure the directories used by the system journal to be owned by "root"."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270764r1066781_rule: Ubuntu 24.04 LTS must configure the files used by the system journal to be owned by "root"
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270764r1066781_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must configure the files used by the system journal to be owned by "root""
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the /run/log/journal and /var/log/journal files are owned by "root" with the following command:

$ sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %U" {} \; 
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/system.journal root
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/user-1000@0005f97cd4a8c9b5-f088232c3718485a.journal~ root
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/system@0005f97cd2a1e0a7-d58b848af46813a4.journal~ root
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/system@0005f97cb900e501-55ea053b7f75ae1c.journal~ root
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/user-1000.journal root

If any output returned is not owned by "root", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %U\" {} \;"
output_0=$(eval "find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %U\" {} \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %U\" {} \;" "SV-270764r1066781_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270764r1066781_rule" "Ubuntu 24.04 LTS must configure the files used by the system journal to be owned by "root""

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270766r1066787_rule: Ubuntu 24.04 LTS must configure the /var/log directory to be owned by root.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270766r1066787_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must configure the /var/log directory to be owned by root."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 24.04 LTS configures the /var/log directory to be owned by "root" with the following command: 
 
$ stat -c "%n %U" /var/log
/var/log root 
 
If the "/var/log" directory is not owned by root, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} stat -c \"%n %U\" /var/log"
output_0=$(eval "stat -c \"%n %U\" /var/log" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "stat -c \"%n %U\" /var/log" "SV-270766r1066787_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270766r1066787_rule" "Ubuntu 24.04 LTS must configure the /var/log directory to be owned by root."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270774r1066811_rule: Ubuntu 24.04 LTS must be a vendor-supported release.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270774r1066811_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must be a vendor-supported release."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the version of Ubuntu 24.04 LTS is vendor supported with the following command:

$ grep DISTRIB_DESCRIPTION /etc/lsb-release 
DISTRIB_DESCRIPTION="Ubuntu 24.04.1 LTS"

If the installed version of Ubuntu 24.04 LTS is not supported, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep DISTRIB_DESCRIPTION /etc/lsb-release"
output_0=$(eval "grep DISTRIB_DESCRIPTION /etc/lsb-release" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep DISTRIB_DESCRIPTION /etc/lsb-release" "SV-270774r1066811_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270774r1066811_rule" "Ubuntu 24.04 LTS must be a vendor-supported release."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270824r1066961_rule: Ubuntu 24.04 LTS must have directories that contain system commands set to a mode of "0755" or less permissive.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270824r1066961_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must have directories that contain system commands set to a mode of "0755" or less permissive."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the system commands directories have mode "0755" or less permissive with the following command: 
 
$ find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" '{}' \; 
 
If any directories are found to be group-writable or world-writable, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c \"%n %a\" '{}' \;"
output_0=$(eval "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c \"%n %a\" '{}' \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c \"%n %a\" '{}' \;" "SV-270824r1066961_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270824r1066961_rule" "Ubuntu 24.04 LTS must have directories that contain system commands set to a mode of "0755" or less permissive."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270825r1066964_rule: Ubuntu 24.04 LTS must have directories that contain system commands owned by root.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270825r1066964_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must have directories that contain system commands owned by root."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the system commands directories are owned by root with the following command: 
 
$ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' \; 
 
If any system commands directories are returned, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c \"%n %U\" '{}' \;"
output_0=$(eval "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c \"%n %U\" '{}' \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c \"%n %U\" '{}' \;" "SV-270825r1066964_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270825r1066964_rule" "Ubuntu 24.04 LTS must have directories that contain system commands owned by root."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-270826r1066967_rule: Ubuntu 24.04 LTS must have directories that contain system commands group-owned by root.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-270826r1066967_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 24.04 LTS must have directories that contain system commands group-owned by root."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the system commands directories are group-owned by root with the following command: 
 
$ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c "%n %G" '{}' \; 
 
If any system commands directories are returned that are not Set Group ID up on execution (SGID) files and owned by a privileged account, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c \"%n %G\" '{}' \;"
output_0=$(eval "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c \"%n %G\" '{}' \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c \"%n %G\" '{}' \;" "SV-270826r1066967_rule")
echo -e "${BLUE}Command 1 Result:${NC} $cmd_result_0"

# If any command fails, the whole rule fails
if [ "$cmd_result_0" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_0" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_0" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-270826r1066967_rule" "Ubuntu 24.04 LTS must have directories that contain system commands group-owned by root."

update_counters "$rule_result"

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
