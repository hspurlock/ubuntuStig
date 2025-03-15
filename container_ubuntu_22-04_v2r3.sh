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
# Check for SV-260481r991589_rule: Ubuntu 22.04 LTS must not have the "ntp" package installed.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260481r991589_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must not have the "ntp" package installed."
echo -e "${BLUE}Requirement Type:${NC} negative"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify that the "ntp" package is not installed by using the following command: 
 
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "negative" "dpkg -l | grep ntp" "SV-260481r991589_rule")
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
print_rule_result "$rule_result" "SV-260481r991589_rule" "Ubuntu 22.04 LTS must not have the "ntp" package installed."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260482r958478_rule: Ubuntu 22.04 LTS must not have the "rsh-server" package installed.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260482r958478_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must not have the "rsh-server" package installed."
echo -e "${BLUE}Requirement Type:${NC} negative"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify the "rsh-server" package is not installed by using the following command:  
  
     $ dpkg -l | grep rsh-server 
  
If the "rsh-server" package is installed, this is a finding.
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "negative" "dpkg -l | grep rsh-server" "SV-260482r958478_rule")
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
print_rule_result "$rule_result" "SV-260482r958478_rule" "Ubuntu 22.04 LTS must not have the "rsh-server" package installed."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260483r987796_rule: Ubuntu 22.04 LTS must not have the "telnet" package installed.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260483r987796_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must not have the "telnet" package installed."
echo -e "${BLUE}Requirement Type:${NC} negative"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify that the "telnetd" package is not installed on Ubuntu 22.04 LTS by using the following command:  
 
     $ dpkg -l | grep telnetd 
 
If the "telnetd" package is installed, this is a finding.
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "negative" "dpkg -l | grep telnetd" "SV-260483r987796_rule")
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
print_rule_result "$rule_result" "SV-260483r987796_rule" "Ubuntu 22.04 LTS must not have the "telnet" package installed."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260485r991559_rule: Ubuntu 22.04 LTS must have directories that contain system commands set to a mode of "755" or less permissive.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260485r991559_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must have directories that contain system commands set to a mode of "755" or less permissive."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the system commands directories have mode "755" or less permissive by using the following command:  
  
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c \"%n %a\" '{}' \;" "SV-260485r991559_rule")
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
print_rule_result "$rule_result" "SV-260485r991559_rule" "Ubuntu 22.04 LTS must have directories that contain system commands set to a mode of "755" or less permissive."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260486r991560_rule: Ubuntu 22.04 LTS must have system commands set to a mode of "755" or less permissive.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260486r991560_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must have system commands set to a mode of "755" or less permissive."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the system commands contained in the following directories have mode "755" or less permissive by using the following command:  
  
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c \"%n %a\" '{}' \;" "SV-260486r991560_rule")
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
print_rule_result "$rule_result" "SV-260486r991560_rule" "Ubuntu 22.04 LTS must have system commands set to a mode of "755" or less permissive."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260487r991560_rule: Ubuntu 22.04 LTS library files must have mode "755" or less permissive.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260487r991560_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS library files must have mode "755" or less permissive."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the systemwide shared library files contained in the directories "/lib", "/lib64", and "/usr/lib" have mode "755" or less permissive by using the following command:  
  
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /lib /lib64 /usr/lib -perm /022 -type f -exec stat -c \"%n %a\" '{}' \;" "SV-260487r991560_rule")
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
print_rule_result "$rule_result" "SV-260487r991560_rule" "Ubuntu 22.04 LTS library files must have mode "755" or less permissive."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260489r958564_rule: Ubuntu 22.04 LTS must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260489r958564_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS has all system log files under the "/var/log" directory with a permission set to "640" or less permissive by using the following command: 
 
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c \"%n %a\" {} \;" "SV-260489r958564_rule")
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
print_rule_result "$rule_result" "SV-260489r958564_rule" "Ubuntu 22.04 LTS must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260490r1014781_rule: Ubuntu 22.04 LTS must generate system journal entries without revealing information that could be exploited by adversaries.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260490r1014781_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate system journal entries without revealing information that could be exploited by adversaries."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the /run/log/journal and /var/log/journal directories have permissions set to "2750" or less permissive by using the following command:

$ sudo find /run/log/journal /var/log/journal -type d -exec stat -c "%n %a" {} \;
/run/log/journal 2750
/var/log/journal 2750
/var/log/journal/3b018e681c904487b11671b9c1987cce 2750 
 
If any output returned has a permission set greater than "2750", this is a finding. 
 
Verify all files in the /run/log/journal and /var/log/journal directories have permissions set to "640" or less permissive by using the following command: 
 
     $ sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %a" {} \; 
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system@99dcc72bb1134aaeae4bf157aa7606f4-0000000000003c7a-0006073f8d1c0fec.journal 640 
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system.journal 640
     /var/log/journal/3b018e681c904487b11671b9c1987cce/user-1000.journal 640 
     /var/log/journal/3b018e681c904487b11671b9c1987cce/user-1000@bdedf14602ff4081a77dc7a6debc8626-00000000000062a6-00060b4b414b617a.journal 640
     /var/log/journal/3b018e681c904487b11671b9c1987cce 
 
If any output returned has a permission set greater than "640", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /run/log/journal /var/log/journal -type d -exec stat -c \"%n %a\" {} \;"
output_0=$(eval "find /run/log/journal /var/log/journal -type d -exec stat -c \"%n %a\" {} \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /run/log/journal /var/log/journal -type d -exec stat -c \"%n %a\" {} \;" "SV-260490r1014781_rule")
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
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %a\" {} \;" "SV-260490r1014781_rule")
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
print_rule_result "$rule_result" "SV-260490r1014781_rule" "Ubuntu 22.04 LTS must generate system journal entries without revealing information that could be exploited by adversaries."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260493r991559_rule: Ubuntu 22.04 LTS must have directories that contain system commands owned by "root".
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260493r991559_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must have directories that contain system commands owned by "root"."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the system commands directories are owned by "root" by using the following command:  
  
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c \"%n %U\" '{}' \;" "SV-260493r991559_rule")
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
print_rule_result "$rule_result" "SV-260493r991559_rule" "Ubuntu 22.04 LTS must have directories that contain system commands owned by "root"."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260494r991559_rule: Ubuntu 22.04 LTS must have directories that contain system commands group-owned by "root".
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260494r991559_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must have directories that contain system commands group-owned by "root"."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the system commands directories are group-owned by "root" by using the following command:  
  
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c \"%n %G\" '{}' \;" "SV-260494r991559_rule")
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
print_rule_result "$rule_result" "SV-260494r991559_rule" "Ubuntu 22.04 LTS must have directories that contain system commands group-owned by "root"."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260495r991560_rule: Ubuntu 22.04 LTS must have system commands owned by "root" or a system account.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260495r991560_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must have system commands owned by "root" or a system account."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the system commands contained in the following directories are owned by "root", or a required system account, by using the following command:  
  
     $ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c "%n %U" '{}' \; 
  
If any system commands are returned and are not owned by a required system account, this is a finding.
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c \"%n %U\" '{}' \;" "SV-260495r991560_rule")
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
print_rule_result "$rule_result" "SV-260495r991560_rule" "Ubuntu 22.04 LTS must have system commands owned by "root" or a system account."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260496r991560_rule: Ubuntu 22.04 LTS must have system commands group-owned by "root" or a system account.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260496r991560_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must have system commands group-owned by "root" or a system account."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the system commands contained in the following directories are group-owned by "root" or a required system account by using the following command:  
  
     $ sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f ! -perm /2000 -exec stat -c "%n %G" '{}' \; 
  
If any system commands are returned that are not Set Group ID upon execution (SGID) files and group-owned by a required system account, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f ! -perm /2000 -exec stat -c \"%n %G\" '{}' \;"
output_0=$(eval "find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f ! -perm /2000 -exec stat -c \"%n %G\" '{}' \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f ! -perm /2000 -exec stat -c \"%n %G\" '{}' \;" "SV-260496r991560_rule")
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
print_rule_result "$rule_result" "SV-260496r991560_rule" "Ubuntu 22.04 LTS must have system commands group-owned by "root" or a system account."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260497r991560_rule: Ubuntu 22.04 LTS library directories must be owned by "root".
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260497r991560_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS library directories must be owned by "root"."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the systemwide shared library directories "/lib", "/lib64", and "/usr/lib" are owned by "root" by using the following command:  
  
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /lib /usr/lib /lib64 ! -user root -type d -exec stat -c \"%n %U\" '{}' \;" "SV-260497r991560_rule")
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
print_rule_result "$rule_result" "SV-260497r991560_rule" "Ubuntu 22.04 LTS library directories must be owned by "root"."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260498r991560_rule: Ubuntu 22.04 LTS library directories must be group-owned by "root".
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260498r991560_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS library directories must be group-owned by "root"."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the systemwide library directories "/lib", "/lib64", and "/usr/lib" are group-owned by "root" by using the following command:  
  
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /lib /usr/lib /lib64 ! -group root -type d -exec stat -c \"%n %G\" '{}' \;" "SV-260498r991560_rule")
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
print_rule_result "$rule_result" "SV-260498r991560_rule" "Ubuntu 22.04 LTS library directories must be group-owned by "root"."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260499r991560_rule: Ubuntu 22.04 LTS library files must be owned by "root".
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260499r991560_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS library files must be owned by "root"."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the systemwide shared library files contained in the directories "/lib", "/lib64", and "/usr/lib" are owned by "root" by using the following command:  
  
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /lib /usr/lib /lib64 ! -user root -type f -exec stat -c \"%n %U\" '{}' \;" "SV-260499r991560_rule")
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
print_rule_result "$rule_result" "SV-260499r991560_rule" "Ubuntu 22.04 LTS library files must be owned by "root"."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260500r991560_rule: Ubuntu 22.04 LTS library files must be group-owned by "root".
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260500r991560_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS library files must be group-owned by "root"."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the systemwide library files contained in the directories "/lib", "/lib64", and "/usr/lib" are group-owned by "root", or a required system account, by using the following command:  
  
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /lib /usr/lib /lib64 ! -group root -type f -exec stat -c \"%n %G\" '{}' \;" "SV-260500r991560_rule")
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
print_rule_result "$rule_result" "SV-260500r991560_rule" "Ubuntu 22.04 LTS library files must be group-owned by "root"."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260501r958566_rule: Ubuntu 22.04 LTS must configure the directories used by the system journal to be owned by "root".
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260501r958566_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must configure the directories used by the system journal to be owned by "root"."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the /run/log/journal and /var/log/journal directories are owned by "root" by using the following command: 
 
     $ sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %U" {} \; 
     /run/log/journal root 
     /var/log/journal root 
     /var/log/journal/3b018e681c904487b11671b9c1987cce root 
 
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /run/log/journal /var/log/journal  -type d -exec stat -c \"%n %U\" {} \;" "SV-260501r958566_rule")
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
print_rule_result "$rule_result" "SV-260501r958566_rule" "Ubuntu 22.04 LTS must configure the directories used by the system journal to be owned by "root"."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260503r958566_rule: Ubuntu 22.04 LTS must configure the files used by the system journal to be owned by "root".
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260503r958566_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must configure the files used by the system journal to be owned by "root"."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the /run/log/journal and /var/log/journal files are owned by "root" by using the following command: 
 
     $ sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %U" {} \; 
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system@99dcc72bb1134aaeae4bf157aa7606f4-0000000000003c7a-0006073f8d1c0fec.journal root 
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system.journal root 
     /var/log/journal/3b018e681c904487b11671b9c1987cce/user-1000.journal root 
     /var/log/journal/3b018e681c904487b11671b9c1987cce/user-1000@bdedf14602ff4081a77dc7a6debc8626-00000000000062a6-00060b4b414b617a.journal root 
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system@99dcc72bb1134aaeae4bf157aa7606f4-0000000000005301-000609a409
593.journal root 
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system@99dcc72bb1134aaeae4bf157aa7606f4-0000000000000001-000604dae53225ee.journal root 
     /var/log/journal/3b018e681c904487b11671b9c1987cce/user-1000@bdedf14602ff4081a77dc7a6debc8626-000000000000083b-000604dae72c7e3b.journal root 
 
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %U\" {} \;" "SV-260503r958566_rule")
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
print_rule_result "$rule_result" "SV-260503r958566_rule" "Ubuntu 22.04 LTS must configure the files used by the system journal to be owned by "root"."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260508r958566_rule: Ubuntu 22.04 LTS must configure the "/var/log" directory to be owned by "root".
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260508r958566_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must configure the "/var/log" directory to be owned by "root"."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS configures the "/var/log" directory to be owned by "root" by using the following command:  
  
     $ stat -c "%n %U" /var/log 
     /var/log root  
  
If the "/var/log" directory is not owned by "root", this is a finding.
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "stat -c \"%n %U\" /var/log" "SV-260508r958566_rule")
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
print_rule_result "$rule_result" "SV-260508r958566_rule" "Ubuntu 22.04 LTS must configure the "/var/log" directory to be owned by "root"."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260513r958524_rule: Ubuntu 22.04 LTS must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260513r958524_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify that all public directories have the public sticky bit set by using the following command:   
  
     $ sudo find / -type d -perm -002 ! -perm -1000 
  
If any public directories are found missing the sticky bit, this is a finding.
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find / -type d -perm -002 ! -perm -1000" "SV-260513r958524_rule")
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
print_rule_result "$rule_result" "SV-260513r958524_rule" "Ubuntu 22.04 LTS must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260542r1015006_rule: Ubuntu 22.04 LTS must prevent direct login into the root account.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260542r1015006_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must prevent direct login into the root account."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS prevents direct logins to the root account by using the following command:  
  
     $ sudo passwd -S root  
     root L 08/09/2022 0 99999 7 -1 
  
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "passwd -S root" "SV-260542r1015006_rule")
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
print_rule_result "$rule_result" "SV-260542r1015006_rule" "Ubuntu 22.04 LTS must prevent direct login into the root account."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260543r958482_rule: Ubuntu 22.04 LTS must uniquely identify interactive users.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260543r958482_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must uniquely identify interactive users."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS contains no duplicate User IDs (UIDs) for interactive users by using the following command:  
  
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "awk -F \":\" 'list[\$3]++{print \$1, \$3}' /etc/passwd" "SV-260543r958482_rule")
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
print_rule_result "$rule_result" "SV-260543r958482_rule" "Ubuntu 22.04 LTS must uniquely identify interactive users."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260545r1015007_rule: Ubuntu 22.04 LTS must enforce 24 hours/one day as the minimum password lifetime. Passwords for new users must have a 24 hours/one day minimum password lifetime restriction.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260545r1015007_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must enforce 24 hours/one day as the minimum password lifetime. Passwords for new users must have a 24 hours/one day minimum password lifetime restriction."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS enforces a 24 hours/one day minimum password lifetime for new user accounts by using the following command:  
  
     $ grep -i pass_min_days /etc/login.defs 
     PASS_MIN_DAYS    1  
  
If "PASS_MIN_DAYS" is less than "1", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i pass_min_days /etc/login.defs"
output_0=$(eval "grep -i pass_min_days /etc/login.defs" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i pass_min_days /etc/login.defs" "SV-260545r1015007_rule")
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
print_rule_result "$rule_result" "SV-260545r1015007_rule" "Ubuntu 22.04 LTS must enforce 24 hours/one day as the minimum password lifetime. Passwords for new users must have a 24 hours/one day minimum password lifetime restriction."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260546r1038967_rule: Ubuntu 22.04 LTS must enforce a 60-day maximum password lifetime restriction. Passwords for new users must have a 60-day maximum password lifetime restriction.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260546r1038967_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must enforce a 60-day maximum password lifetime restriction. Passwords for new users must have a 60-day maximum password lifetime restriction."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS enforces a 60-day maximum password lifetime for new user accounts by using the following command: 
  
     $ grep -i pass_max_days /etc/login.defs 
     PASS_MAX_DAYS    60  
 
If "PASS_MAX_DAYS" is less than "60", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i pass_max_days /etc/login.defs"
output_0=$(eval "grep -i pass_max_days /etc/login.defs" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i pass_max_days /etc/login.defs" "SV-260546r1038967_rule")
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
print_rule_result "$rule_result" "SV-260546r1038967_rule" "Ubuntu 22.04 LTS must enforce a 60-day maximum password lifetime restriction. Passwords for new users must have a 60-day maximum password lifetime restriction."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260547r1015009_rule: Ubuntu 22.04 LTS must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260547r1015009_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the account identifiers (individuals, groups, roles, and devices) are disabled after 35 days of inactivity by using the following command:  
  
Check the account inactivity value by performing the following command:  
  
     $ grep INACTIVE /etc/default/useradd  
     INACTIVE=35  
  
If "INACTIVE" is set to "-1" or is not set to "35", is commented out, or is missing, this is a finding.
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep INACTIVE /etc/default/useradd" "SV-260547r1015009_rule")
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
print_rule_result "$rule_result" "SV-260547r1015009_rule" "Ubuntu 22.04 LTS must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260548r958364_rule: Ubuntu 22.04 LTS must automatically expire temporary accounts within 72 hours.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260548r958364_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must automatically expire temporary accounts within 72 hours."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify temporary accounts have been provisioned with an expiration date of 72 hours by using the following command: 
 
     $ sudo chage -l  | grep -E '(Password|Account) expires' 
     Password expires     : Apr 1, 2024  
     Account expires        : Apr 1, 2024  
 
Verify each of these accounts has an expiration date set within 72 hours. 
 
If any temporary accounts have no expiration date set or do not expire within 72 hours, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} chage -l  | grep -E '(Password|Account) expires'"
output_0=$(eval "chage -l  | grep -E '(Password|Account) expires'" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "chage -l  | grep -E '(Password|Account) expires'" "SV-260548r958364_rule")
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
print_rule_result "$rule_result" "SV-260548r958364_rule" "Ubuntu 22.04 LTS must automatically expire temporary accounts within 72 hours."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260552r958398_rule: Ubuntu 22.04 LTS must limit the number of concurrent sessions to ten for all accounts and/or account types.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260552r958398_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must limit the number of concurrent sessions to ten for all accounts and/or account types."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS limits the number of concurrent sessions to 10 for all accounts and/or account types by using the following command:  
  
     $ sudo grep -r -s '^[^#].*maxlogins' /etc/security/limits.conf /etc/security/limits.d/*.conf 
     /etc/security/limits.conf:* hard maxlogins 10 
 
If "maxlogins" does not have a value of "10" or less, is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -r -s \"^[^#].*maxlogins\" /etc/security/limits.conf /etc/security/limits.d/*.conf"
output_0=$(eval "grep -r -s \"^[^#].*maxlogins\" /etc/security/limits.conf /etc/security/limits.d/*.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -r -s \"^[^#].*maxlogins\" /etc/security/limits.conf /etc/security/limits.d/*.conf" "SV-260552r958398_rule")
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
print_rule_result "$rule_result" "SV-260552r958398_rule" "Ubuntu 22.04 LTS must limit the number of concurrent sessions to ten for all accounts and/or account types."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260553r1015010_rule: Ubuntu 22.04 LTS must allow users to directly initiate a session lock for all connection types.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260553r1015010_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must allow users to directly initiate a session lock for all connection types."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS has the "vlock" package installed by using the following command:  
  
     $ dpkg -l | grep vlock 
     ii     vlock     2.2.2-10     amd64     Virtual Console locking program 
  
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "dpkg -l | grep vlock" "SV-260553r1015010_rule")
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
print_rule_result "$rule_result" "SV-260553r1015010_rule" "Ubuntu 22.04 LTS must allow users to directly initiate a session lock for all connection types."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260554r958636_rule: Ubuntu 22.04 LTS must automatically exit interactive command shell user sessions after 15 minutes of inactivity.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260554r958636_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must automatically exit interactive command shell user sessions after 15 minutes of inactivity."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS is configured to automatically exit interactive command shell user sessions after 15 minutes of inactivity or less by using the following command: 
  
     $ sudo grep -E "\bTMOUT=[0-9]+" /etc/bash.bashrc /etc/profile.d/* 
     /etc/profile.d/99-terminal_tmout.sh:TMOUT=900 
  
If "TMOUT" is not set to "900" or less, is set to "0", is commented out, or missing, this is a finding.
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -E \"\bTMOUT=[0-9]+\" /etc/bash.bashrc /etc/profile.d/*" "SV-260554r958636_rule")
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
print_rule_result "$rule_result" "SV-260554r958636_rule" "Ubuntu 22.04 LTS must automatically exit interactive command shell user sessions after 15 minutes of inactivity."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260558r1050789_rule: Ubuntu 22.04 LTS must require users to reauthenticate for privilege escalation or when changing roles.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260558r1050789_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must require users to reauthenticate for privilege escalation or when changing roles."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the "/etc/sudoers" file has no occurrences of "NOPASSWD" or "!authenticate" by using the following command:  
  
     $ sudo grep -Ei '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/* 
  
If any occurrences of "NOPASSWD" or "!authenticate" return from the command, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -Ei '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*"
output_0=$(eval "grep -Ei '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -Ei '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*" "SV-260558r1050789_rule")
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
print_rule_result "$rule_result" "SV-260558r1050789_rule" "Ubuntu 22.04 LTS must require users to reauthenticate for privilege escalation or when changing roles."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260559r958518_rule: Ubuntu 22.04 LTS must ensure only users who need access to security functions are part of sudo group.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260559r958518_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must ensure only users who need access to security functions are part of sudo group."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the sudo group has only members who require access to security functions by using the following command:   
  
     $ grep sudo /etc/group  
     sudo:x:27: 
  
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep sudo /etc/group" "SV-260559r958518_rule")
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
print_rule_result "$rule_result" "SV-260559r958518_rule" "Ubuntu 22.04 LTS must ensure only users who need access to security functions are part of sudo group."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260560r1015012_rule: Ubuntu 22.04 LTS must enforce password complexity by requiring at least one uppercase character be used.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260560r1015012_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must enforce password complexity by requiring at least one uppercase character be used."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS enforces password complexity by requiring at least one uppercase character be used by using the following command:  
  
     $ grep -i ucredit /etc/security/pwquality.conf 
     ucredit = -1  
  
If "ucredit" is greater than "-1", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i ucredit /etc/security/pwquality.conf"
output_0=$(eval "grep -i ucredit /etc/security/pwquality.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i ucredit /etc/security/pwquality.conf" "SV-260560r1015012_rule")
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
print_rule_result "$rule_result" "SV-260560r1015012_rule" "Ubuntu 22.04 LTS must enforce password complexity by requiring at least one uppercase character be used."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260561r1015013_rule: Ubuntu 22.04 LTS must enforce password complexity by requiring at least one lowercase character be used.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260561r1015013_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must enforce password complexity by requiring at least one lowercase character be used."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS enforces password complexity by requiring that at least one lowercase character be used by using the following command:  
  
     $ grep -i lcredit /etc/security/pwquality.conf 
     lcredit = -1  
  
If "lcredit" is greater than "-1", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i lcredit /etc/security/pwquality.conf"
output_0=$(eval "grep -i lcredit /etc/security/pwquality.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i lcredit /etc/security/pwquality.conf" "SV-260561r1015013_rule")
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
print_rule_result "$rule_result" "SV-260561r1015013_rule" "Ubuntu 22.04 LTS must enforce password complexity by requiring at least one lowercase character be used."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260562r1015014_rule: Ubuntu 22.04 LTS must enforce password complexity by requiring that at least one numeric character be used.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260562r1015014_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must enforce password complexity by requiring that at least one numeric character be used."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS enforces password complexity by requiring that at least one numeric character be used by using the following command: 
 
     $ grep -i dcredit /etc/security/pwquality.conf 
     dcredit = -1  
  
If "dcredit" is greater than "-1", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i dcredit /etc/security/pwquality.conf"
output_0=$(eval "grep -i dcredit /etc/security/pwquality.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i dcredit /etc/security/pwquality.conf" "SV-260562r1015014_rule")
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
print_rule_result "$rule_result" "SV-260562r1015014_rule" "Ubuntu 22.04 LTS must enforce password complexity by requiring that at least one numeric character be used."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260563r1015015_rule: Ubuntu 22.04 LTS must enforce password complexity by requiring that at least one special character be used.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260563r1015015_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must enforce password complexity by requiring that at least one special character be used."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS enforces password complexity by requiring that at least one special character be used by using the following command: 
  
     $ grep -i ocredit /etc/security/pwquality.conf 
     ocredit = -1  
  
If "ocredit" is greater than "-1", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i ocredit /etc/security/pwquality.conf"
output_0=$(eval "grep -i ocredit /etc/security/pwquality.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i ocredit /etc/security/pwquality.conf" "SV-260563r1015015_rule")
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
print_rule_result "$rule_result" "SV-260563r1015015_rule" "Ubuntu 22.04 LTS must enforce password complexity by requiring that at least one special character be used."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260564r991587_rule: Ubuntu 22.04 LTS must prevent the use of dictionary words for passwords.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260564r991587_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must prevent the use of dictionary words for passwords."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS prevents the use of dictionary words for passwords by using the following command: 
 
     $ grep -i dictcheck /etc/security/pwquality.conf 
     dictcheck = 1  
  
If "dictcheck" is not set to "1", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i dictcheck /etc/security/pwquality.conf"
output_0=$(eval "grep -i dictcheck /etc/security/pwquality.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i dictcheck /etc/security/pwquality.conf" "SV-260564r991587_rule")
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
print_rule_result "$rule_result" "SV-260564r991587_rule" "Ubuntu 22.04 LTS must prevent the use of dictionary words for passwords."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260565r1015016_rule: Ubuntu 22.04 LTS must enforce a minimum 15-character password length.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260565r1015016_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must enforce a minimum 15-character password length."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify the pwquality configuration file enforces a minimum 15-character password length by using the following command: 
 
     $ grep -i minlen /etc/security/pwquality.conf 
     minlen = 15 
 
If "minlen" is not "15" or higher, is commented out, or is missing, this is a finding.
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i minlen /etc/security/pwquality.conf" "SV-260565r1015016_rule")
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
print_rule_result "$rule_result" "SV-260565r1015016_rule" "Ubuntu 22.04 LTS must enforce a minimum 15-character password length."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260566r1015017_rule: Ubuntu 22.04 LTS must require the change of at least eight characters when passwords are changed.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260566r1015017_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must require the change of at least eight characters when passwords are changed."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS requires the change of at least eight characters when passwords are changed by using the following command: 
  
     $ grep -i difok /etc/security/pwquality.conf 
     difok = 8  
  
If "difok" is less than "8", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i difok /etc/security/pwquality.conf"
output_0=$(eval "grep -i difok /etc/security/pwquality.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i difok /etc/security/pwquality.conf" "SV-260566r1015017_rule")
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
print_rule_result "$rule_result" "SV-260566r1015017_rule" "Ubuntu 22.04 LTS must require the change of at least eight characters when passwords are changed."

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260571r991589_rule: Ubuntu 22.04 LTS must not have accounts configured with blank or null passwords.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260571r991589_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must not have accounts configured with blank or null passwords."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify all accounts on the system to have a password by using the following command: 
 
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "awk -F: '!\$2 {print \$1}' /etc/shadow" "SV-260571r991589_rule")
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
print_rule_result "$rule_result" "SV-260571r991589_rule" "Ubuntu 22.04 LTS must not have accounts configured with blank or null passwords."

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
