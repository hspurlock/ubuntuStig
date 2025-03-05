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
# Check for SV-260469r991589_rule: Ubuntu 22.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260469r991589_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} service\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS is not configured to reboot the system when Ctrl-Alt-Delete is pressed by using the following command: 
 
     $ systemctl status ctrl-alt-del.target 
     ctrl-alt-del.target 
          Loaded: masked (Reason: Unit ctrl-alt-del.target is masked.) 
          Active: inactive (dead) 
 
If the "ctrl-alt-del.target" is not masked, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} systemctl status ctrl-alt-del.target"
output_0=$(eval "systemctl status ctrl-alt-del.target" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "systemctl status ctrl-alt-del.target" "SV-260469r991589_rule")
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
print_rule_result "$rule_result" "SV-260469r991589_rule" "Ubuntu 22.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260469r991589_rule", "$stig_result", "systemctl status ctrl-alt-del.target", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260470r958472_rule: Ubuntu 22.04 LTS, when booted, must require authentication upon booting into single-user and maintenance modes.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260470r958472_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS, when booted, must require authentication upon booting into single-user and maintenance modes."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS requires a password for authentication upon booting into single-user and maintenance modes by using the following command:  
  
     $ sudo grep -i password /boot/grub/grub.cfg  
  
     password_pbkdf2 root grub.pbkdf2.sha512.10000.03255F190F0E2F7B4F0D1C3216012309162F022A7A636771 
  
If the root password entry does not begin with "password_pbkdf2", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i password /boot/grub/grub.cfg"
output_0=$(eval "grep -i password /boot/grub/grub.cfg" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i password /boot/grub/grub.cfg" "SV-260470r958472_rule")
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
print_rule_result "$rule_result" "SV-260470r958472_rule" "Ubuntu 22.04 LTS, when booted, must require authentication upon booting into single-user and maintenance modes."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260470r958472_rule", "$stig_result", "grep -i password /boot/grub/grub.cfg", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260471r991555_rule: Ubuntu 22.04 LTS must initiate session audits at system startup.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260471r991555_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must initiate session audits at system startup."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify that Ubuntu 22.04 LTS enables auditing at system startup in grub by using the following command:
  
     $ grep "^\s*linux" /boot/grub/grub.cfg 
 
     linux   /vmlinuz-5.15.0-89-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro audit=1 
          linux   /vmlinuz-5.15.0-89-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro audit=1 
          linux   /vmlinuz-5.15.0-89-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro single nomodeset dis_ucode_ldr audit=1 
          linux   /vmlinuz-5.15.0-83-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro audit=1 
          linux   /vmlinuz-5.15.0-83-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro single nomodeset dis_ucode_ldr audit=1 
 
If any linux lines do not contain "audit=1", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep \"^\s*linux\" /boot/grub/grub.cfg"
output_0=$(eval "grep \"^\s*linux\" /boot/grub/grub.cfg" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep \"^\s*linux\" /boot/grub/grub.cfg" "SV-260471r991555_rule")
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
print_rule_result "$rule_result" "SV-260471r991555_rule" "Ubuntu 22.04 LTS must initiate session audits at system startup."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260471r991555_rule", "$stig_result", "grep \"^\s*linux\" /boot/grub/grub.cfg", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260472r958524_rule: Ubuntu 22.04 LTS must restrict access to the kernel message buffer.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260472r958524_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must restrict access to the kernel message buffer."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS is configured to restrict access to the kernel message buffer by using the following command: 
 
     $ sysctl kernel.dmesg_restrict 
     kernel.dmesg_restrict = 1 
 
If "kernel.dmesg_restrict" is not set to "1" or is missing, this is a finding. 
 
Verify that there are no configurations that enable the kernel dmesg function: 
 
     $ sudo grep -ir kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null 
     /etc/sysctl.d/10-kernel-hardening.conf:kernel.dmesg_restrict = 1 
 
If "kernel.dmesg_restrict" is not set to "1", is commented out, is missing, or conflicting results are returned, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} sysctl kernel.dmesg_restrict"
output_0=$(eval "sysctl kernel.dmesg_restrict" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "sysctl kernel.dmesg_restrict" "SV-260472r958524_rule")
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
echo -e "${BLUE}Executing:${NC} grep -ir kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null"
output_1=$(eval "grep -ir kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "grep -ir kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null" "SV-260472r958524_rule")
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
print_rule_result "$rule_result" "SV-260472r958524_rule" "Ubuntu 22.04 LTS must restrict access to the kernel message buffer."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260472r958524_rule", "$stig_result", "grep -ir kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null", "$output_1"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260473r958550_rule: Ubuntu 22.04 LTS must disable kernel core dumps so that it can fail to a secure state if system initialization fails, shutdown fails or aborts fail.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260473r958550_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must disable kernel core dumps so that it can fail to a secure state if system initialization fails, shutdown fails or aborts fail."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} service\n"

# Check Content:
cat << 'EOF'
Verify that kernel core dumps are disabled unless needed by using the following command:  
  
     $ systemctl status kdump.service 
     kdump.service 
          Loaded: masked (Reason: Unit kdump.service is masked.) 
          Active: inactive (dead) 
  
If "kdump.service" is not masked and inactive, ask the system administrator (SA) if the use of the service is required and documented with the information system security officer (ISSO).  
  
If the service is active and is not documented, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} systemctl status kdump.service"
output_0=$(eval "systemctl status kdump.service" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "systemctl status kdump.service" "SV-260473r958550_rule")
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
print_rule_result "$rule_result" "SV-260473r958550_rule" "Ubuntu 22.04 LTS must disable kernel core dumps so that it can fail to a secure state if system initialization fails, shutdown fails or aborts fail."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260473r958550_rule", "$stig_result", "systemctl status kdump.service", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260474r958928_rule: Ubuntu 22.04 LTS must implement address space layout randomization to protect its memory from unauthorized code execution.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260474r958928_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must implement address space layout randomization to protect its memory from unauthorized code execution."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS implements address space layout randomization (ASLR) by using the following command:  
  
     $ sysctl kernel.randomize_va_space 
     kernel.randomize_va_space = 2 
  
If no output is returned, verify the kernel parameter "randomize_va_space" is set to "2" by using the following command:  
  
     $ cat /proc/sys/kernel/randomize_va_space 
     2 
  
If "kernel.randomize_va_space" is not set to "2", this is a finding.  
  
Verify that a saved value of the "kernel.randomize_va_space" variable is not defined.  
  
     $ sudo grep -ER "^kernel.randomize_va_space=[^2]" /etc/sysctl.conf /etc/sysctl.d 
  
If this returns a result, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} sysctl kernel.randomize_va_space"
output_0=$(eval "sysctl kernel.randomize_va_space" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "sysctl kernel.randomize_va_space" "SV-260474r958928_rule")
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
echo -e "${BLUE}Executing:${NC} cat /proc/sys/kernel/randomize_va_space"
output_1=$(eval "cat /proc/sys/kernel/randomize_va_space" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "cat /proc/sys/kernel/randomize_va_space" "SV-260474r958928_rule")
echo -e "${BLUE}Command 2 Result:${NC} $cmd_result_1"

# If any command fails, the whole rule fails
if [ "$cmd_result_1" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_1" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_1" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Command 3
echo -e "${BLUE}Executing:${NC} grep -ER \"^kernel.randomize_va_space=[^2]\" /etc/sysctl.conf /etc/sysctl.d"
output_2=$(eval "grep -ER \"^kernel.randomize_va_space=[^2]\" /etc/sysctl.conf /etc/sysctl.d" 2>&1)
exit_code_2=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_2"
echo -e "${BLUE}Output:${NC}"
echo "$output_2"
echo ""

# Evaluate command result using function
cmd_result_2=$(evaluate_command_result "$exit_code_2" "$output_2" "positive" "grep -ER \"^kernel.randomize_va_space=[^2]\" /etc/sysctl.conf /etc/sysctl.d" "SV-260474r958928_rule")
echo -e "${BLUE}Command 3 Result:${NC} $cmd_result_2"

# If any command fails, the whole rule fails
if [ "$cmd_result_2" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_2" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_2" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-260474r958928_rule" "Ubuntu 22.04 LTS must implement address space layout randomization to protect its memory from unauthorized code execution."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260474r958928_rule", "$stig_result", "grep -ER \"^kernel.randomize_va_space=[^2]\" /etc/sysctl.conf /etc/sysctl.d", "$output_2"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260475r958928_rule: Ubuntu 22.04 LTS must implement nonexecutable data to protect its memory from unauthorized code execution.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260475r958928_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must implement nonexecutable data to protect its memory from unauthorized code execution."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify the NX (no-execution) bit flag is set on the system by using the following command:  
 
     $ sudo dmesg | grep -i "execute disable" 
     [    0.000000] NX (Execute Disable) protection: active  
 
If "dmesg" does not show "NX (Execute Disable) protection: active", check the hardware capabilities of the installed CPU by using the following command:   
  
     $ grep flags /proc/cpuinfo | grep -o nx | sort -u 
     nx  
  
If no output is returned, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} dmesg | grep -i \"execute disable\""
output_0=$(eval "dmesg | grep -i \"execute disable\"" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "dmesg | grep -i \"execute disable\"" "SV-260475r958928_rule")
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
echo -e "${BLUE}Executing:${NC} grep flags /proc/cpuinfo | grep -o nx | sort -u"
output_1=$(eval "grep flags /proc/cpuinfo | grep -o nx | sort -u" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "grep flags /proc/cpuinfo | grep -o nx | sort -u" "SV-260475r958928_rule")
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
print_rule_result "$rule_result" "SV-260475r958928_rule" "Ubuntu 22.04 LTS must implement nonexecutable data to protect its memory from unauthorized code execution."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260475r958928_rule", "$stig_result", "grep flags /proc/cpuinfo | grep -o nx | sort -u", "$output_1"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260476r1015003_rule: Ubuntu 22.04 LTS must be configured so that the Advance Package Tool (APT) prevents the installation of patches, service packs, device drivers, or operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260476r1015003_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must be configured so that the Advance Package Tool (APT) prevents the installation of patches, service packs, device drivers, or operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that APT is configured to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization by using the following command:  
  
     $ grep -i allowunauthenticated /etc/apt/apt.conf.d/* 
     /etc/apt/apt.conf.d/01-vendor-ubuntu:APT::Get::AllowUnauthenticated "false"; 
  
If "APT::Get::AllowUnauthenticated" is not set to "false", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i allowunauthenticated /etc/apt/apt.conf.d/*"
output_0=$(eval "grep -i allowunauthenticated /etc/apt/apt.conf.d/*" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i allowunauthenticated /etc/apt/apt.conf.d/*" "SV-260476r1015003_rule")
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
print_rule_result "$rule_result" "SV-260476r1015003_rule" "Ubuntu 22.04 LTS must be configured so that the Advance Package Tool (APT) prevents the installation of patches, service packs, device drivers, or operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260476r1015003_rule", "$stig_result", "grep -i allowunauthenticated /etc/apt/apt.conf.d/*", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260477r958936_rule: Ubuntu 22.04 LTS must be configured so that the Advance Package Tool (APT) removes all software components after updated versions have been installed.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260477r958936_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must be configured so that the Advance Package Tool (APT) removes all software components after updated versions have been installed."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify APT is configured to remove all software components after updated versions have been installed by using the following command:  
  
     $ grep -i remove-unused /etc/apt/apt.conf.d/50-unattended-upgrades 
     Unattended-Upgrade::Remove-Unused-Kernel-Packages "true"; 
     Unattended-Upgrade::Remove-Unused-Dependencies "true"; 
  
If "Unattended-Upgrade::Remove-Unused-Kernel-Packages" and "Unattended-Upgrade::Remove-Unused-Dependencies" are not set to "true", are commented out, or are missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i remove-unused /etc/apt/apt.conf.d/50-unattended-upgrades"
output_0=$(eval "grep -i remove-unused /etc/apt/apt.conf.d/50-unattended-upgrades" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i remove-unused /etc/apt/apt.conf.d/50-unattended-upgrades" "SV-260477r958936_rule")
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
print_rule_result "$rule_result" "SV-260477r958936_rule" "Ubuntu 22.04 LTS must be configured so that the Advance Package Tool (APT) removes all software components after updated versions have been installed."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260477r958936_rule", "$stig_result", "grep -i remove-unused /etc/apt/apt.conf.d/50-unattended-upgrades", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260478r991587_rule: Ubuntu 22.04 LTS must have the "libpam-pwquality" package installed.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260478r991587_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must have the "libpam-pwquality" package installed."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS has the "libpam-pwquality" package installed with  the following command:  
  
     $ dpkg -l | grep libpam-pwquality 
     ii     libpam-pwquality:amd64     1.4.4-1build2     amd64     PAM module to check password strength 
  
If "libpam-pwquality" is not installed, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} dpkg -l | grep libpam-pwquality"
output_0=$(eval "dpkg -l | grep libpam-pwquality" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "dpkg -l | grep libpam-pwquality" "SV-260478r991587_rule")
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
print_rule_result "$rule_result" "SV-260478r991587_rule" "Ubuntu 22.04 LTS must have the "libpam-pwquality" package installed."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260478r991587_rule", "$stig_result", "dpkg -l | grep libpam-pwquality", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260479r991589_rule: Ubuntu 22.04 LTS must have the "chrony" package installed.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260479r991589_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must have the "chrony" package installed."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify the "chrony" package is installed using the following command: 
  
     $ dpkg -l | grep chrony 
     ii     chrony     4.2-2ubuntu2     amd64     Versatile implementation of the Network Time Protocol 
 
If the "chrony" package is not installed, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} dpkg -l | grep chrony"
output_0=$(eval "dpkg -l | grep chrony" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "dpkg -l | grep chrony" "SV-260479r991589_rule")
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
print_rule_result "$rule_result" "SV-260479r991589_rule" "Ubuntu 22.04 LTS must have the "chrony" package installed."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260479r991589_rule", "$stig_result", "dpkg -l | grep chrony", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260480r991589_rule: Ubuntu 22.04 LTS must not have the "systemd-timesyncd" package installed.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260480r991589_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must not have the "systemd-timesyncd" package installed."
echo -e "${BLUE}Requirement Type:${NC} negative"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify that the "systemd-timesyncd" package is not installed by using the following command: 
 
     $ dpkg -l | grep systemd-timesyncd 
 
If the "systemd-timesyncd" package is installed, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} dpkg -l | grep systemd-timesyncd"
output_0=$(eval "dpkg -l | grep systemd-timesyncd" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "negative" "dpkg -l | grep systemd-timesyncd" "SV-260480r991589_rule")
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
print_rule_result "$rule_result" "SV-260480r991589_rule" "Ubuntu 22.04 LTS must not have the "systemd-timesyncd" package installed."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260480r991589_rule", "$stig_result", "dpkg -l | grep systemd-timesyncd", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260481r991589_rule", "$stig_result", "dpkg -l | grep ntp", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260482r958478_rule", "$stig_result", "dpkg -l | grep rsh-server", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260483r987796_rule", "$stig_result", "dpkg -l | grep telnetd", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260484r958552_rule: Ubuntu 22.04 LTS must implement cryptographic mechanisms to prevent unauthorized disclosure and modification of all information that requires protection at rest.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260484r958552_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must implement cryptographic mechanisms to prevent unauthorized disclosure and modification of all information that requires protection at rest."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS prevents unauthorized disclosure or modification of all information requiring at-rest protection by using disk encryption.   
 
Note: If there is a documented and approved reason for not having data-at-rest encryption, this requirement is not applicable. 
  
Determine the partition layout for the system by using the following command:  
  
     $ sudo fdisk -l 
 
     ... 
     Device               Start               End        Sectors       Size  Type 
     /dev/sda1         2048      2203647       2201600          1G  EFI System 
     /dev/sda2  2203648      6397951       4194304          2G  Linux filesystem 
     /dev/sda3  6397952  536868863  530470912  252.9G  Linux filesystem 
     ... 
  
Verify the system partitions are all encrypted by using the following command:  
 
     # more /etc/crypttab 
 
Every persistent disk partition present must have an entry in the file.   
  
If any partitions other than the boot partition or pseudo file systems (such as /proc or /sys) are not listed, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} fdisk -l"
output_0=$(eval "fdisk -l" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "fdisk -l" "SV-260484r958552_rule")
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
print_rule_result "$rule_result" "SV-260484r958552_rule" "Ubuntu 22.04 LTS must implement cryptographic mechanisms to prevent unauthorized disclosure and modification of all information that requires protection at rest."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260484r958552_rule", "$stig_result", "fdisk -l", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260485r991559_rule", "$stig_result", "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c \"%n %a\" '{}' \;", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260486r991560_rule", "$stig_result", "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c \"%n %a\" '{}' \;", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260487r991560_rule", "$stig_result", "find /lib /lib64 /usr/lib -perm /022 -type f -exec stat -c \"%n %a\" '{}' \;", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260488r958566_rule: Ubuntu 22.04 LTS must configure the "/var/log" directory to have mode "755" or less permissive.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260488r958566_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must configure the "/var/log" directory to have mode "755" or less permissive."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the "/var/log" directory has mode of "755" or less permissive by using the following command: 
 
Note: If rsyslog is active and enabled on the operating system, this requirement is not applicable. 
 
     $ stat -c "%n %a" /var/log 
     /var/log 755 
 
If a value of "755" or less permissive is not returned, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} stat -c \"%n %a\" /var/log"
output_0=$(eval "stat -c \"%n %a\" /var/log" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "stat -c \"%n %a\" /var/log" "SV-260488r958566_rule")
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
print_rule_result "$rule_result" "SV-260488r958566_rule" "Ubuntu 22.04 LTS must configure the "/var/log" directory to have mode "755" or less permissive."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260488r958566_rule", "$stig_result", "stat -c \"%n %a\" /var/log", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260489r958564_rule", "$stig_result", "find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c \"%n %a\" {} \;", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260490r1014781_rule", "$stig_result", "find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %a\" {} \;", "$output_1"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260491r958566_rule: Ubuntu 22.04 LTS must configure "/var/log/syslog" file with mode "640" or less permissive.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260491r958566_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must configure "/var/log/syslog" file with mode "640" or less permissive."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that Ubuntu 22.04 LTS configures the "/var/log/syslog" file with mode "640" or less permissive by using the following command:  
  
     $ stat -c "%n %a" /var/log/syslog  
     /var/log/syslog 640  
  
If a value of "640" or less permissive is not returned, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} stat -c \"%n %a\" /var/log/syslog"
output_0=$(eval "stat -c \"%n %a\" /var/log/syslog" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "stat -c \"%n %a\" /var/log/syslog" "SV-260491r958566_rule")
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
print_rule_result "$rule_result" "SV-260491r958566_rule" "Ubuntu 22.04 LTS must configure "/var/log/syslog" file with mode "640" or less permissive."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260491r958566_rule", "$stig_result", "stat -c \"%n %a\" /var/log/syslog", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260492r991557_rule: Ubuntu 22.04 LTS must configure audit tools with a mode of "755" or less permissive.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260492r991557_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must configure audit tools with a mode of "755" or less permissive."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS configures the audit tools to have a file permission of "755" or less to prevent unauthorized access by using the following command:  
  
     $ stat -c "%n %a" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules 
     /sbin/auditctl 755 
     /sbin/aureport 755 
     /sbin/ausearch 755 
     /sbin/autrace 755 
     /sbin/auditd 755 
     /sbin/audispd-zos-remote 755 
     /sbin/augenrules 755 
  
If any of the audit tools have a mode more permissive than "0755", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} stat -c \"%n %a\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules"
output_0=$(eval "stat -c \"%n %a\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "stat -c \"%n %a\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules" "SV-260492r991557_rule")
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
print_rule_result "$rule_result" "SV-260492r991557_rule" "Ubuntu 22.04 LTS must configure audit tools with a mode of "755" or less permissive."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260492r991557_rule", "$stig_result", "stat -c \"%n %a\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260493r991559_rule", "$stig_result", "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c \"%n %U\" '{}' \;", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260494r991559_rule", "$stig_result", "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c \"%n %G\" '{}' \;", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260495r991560_rule", "$stig_result", "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c \"%n %U\" '{}' \;", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260496r991560_rule", "$stig_result", "find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f ! -perm /2000 -exec stat -c \"%n %G\" '{}' \;", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260497r991560_rule", "$stig_result", "find /lib /usr/lib /lib64 ! -user root -type d -exec stat -c \"%n %U\" '{}' \;", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260498r991560_rule", "$stig_result", "find /lib /usr/lib /lib64 ! -group root -type d -exec stat -c \"%n %G\" '{}' \;", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260499r991560_rule", "$stig_result", "find /lib /usr/lib /lib64 ! -user root -type f -exec stat -c \"%n %U\" '{}' \;", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260500r991560_rule", "$stig_result", "find /lib /usr/lib /lib64 ! -group root -type f -exec stat -c \"%n %G\" '{}' \;", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260501r958566_rule", "$stig_result", "find /run/log/journal /var/log/journal  -type d -exec stat -c \"%n %U\" {} \;", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260502r958566_rule: Ubuntu 22.04 LTS must configure the directories used by the system journal to be group-owned by "systemd-journal".
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260502r958566_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must configure the directories used by the system journal to be group-owned by "systemd-journal"."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the /run/log/journal and /var/log/journal directories are group-owned by "systemd-journal" by using the following command: 
 
     $ sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %G" {} \; 
     /run/log/journal systemd-journal 
     /var/log/journal systemd-journal 
     /var/log/journal/3b018e681c904487b11671b9c1987cce systemd-journal 
 
If any output returned is not group-owned by "systemd-journal", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /run/log/journal /var/log/journal  -type d -exec stat -c \"%n %G\" {} \;"
output_0=$(eval "find /run/log/journal /var/log/journal  -type d -exec stat -c \"%n %G\" {} \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /run/log/journal /var/log/journal  -type d -exec stat -c \"%n %G\" {} \;" "SV-260502r958566_rule")
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
print_rule_result "$rule_result" "SV-260502r958566_rule" "Ubuntu 22.04 LTS must configure the directories used by the system journal to be group-owned by "systemd-journal"."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260502r958566_rule", "$stig_result", "find /run/log/journal /var/log/journal  -type d -exec stat -c \"%n %G\" {} \;", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260503r958566_rule", "$stig_result", "find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %U\" {} \;", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260504r958566_rule: Ubuntu 22.04 LTS must configure the files used by the system journal to be group-owned by "systemd-journal".
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260504r958566_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must configure the files used by the system journal to be group-owned by "systemd-journal"."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the /run/log/journal and /var/log/journal files are group-owned by "systemd-journal" by using the following command: 
 
     $ sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %G" {} \; 
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system@99dcc72bb1134aaeae4bf157aa7606f4-0000000000003c7a-0006073f8d1c0fec.journal systemd-journal 
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system.journal systemd-journal 
     /var/log/journal/3b018e681c904487b11671b9c1987cce/user-1000.journal systemd-journal 
     /var/log/journal/3b018e681c904487b11671b9c1987cce/user-1000@bdedf14602ff4081a77dc7a6debc8626-00000000000062a6-00060b4b414b617a.journal systemd-journal 
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system@99dcc72bb1134aaeae4bf157aa7606f4-0000000000005301-000609a409
593.journal systemd-journal 
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system@99dcc72bb1134aaeae4bf157aa7606f4-0000000000000001-000604dae53225ee.journal systemd-journal 
     /var/log/journal/3b018e681c904487b11671b9c1987cce/user-1000@bdedf14602ff4081a77dc7a6debc8626-000000000000083b-000604dae72c7e3b.journal systemd-journal 
 
If any output returned is not group-owned by "systemd-journal", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %G\" {} \;"
output_0=$(eval "find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %G\" {} \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %G\" {} \;" "SV-260504r958566_rule")
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
print_rule_result "$rule_result" "SV-260504r958566_rule" "Ubuntu 22.04 LTS must configure the files used by the system journal to be group-owned by "systemd-journal"."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260504r958566_rule", "$stig_result", "find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %G\" {} \;", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260505r958566_rule: Ubuntu 22.04 LTS must be configured so that the "journalctl" command is owned by "root".
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260505r958566_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must be configured so that the "journalctl" command is owned by "root"."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify that the "journalctl" command is owned by "root" by using the following command: 
 
     $ sudo find /usr/bin/journalctl -exec stat -c "%n %U" {} \; 
     /usr/bin/journalctl root 
 
If "journalctl" is not owned by "root", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /usr/bin/journalctl -exec stat -c \"%n %U\" {} \;"
output_0=$(eval "find /usr/bin/journalctl -exec stat -c \"%n %U\" {} \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /usr/bin/journalctl -exec stat -c \"%n %U\" {} \;" "SV-260505r958566_rule")
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
print_rule_result "$rule_result" "SV-260505r958566_rule" "Ubuntu 22.04 LTS must be configured so that the "journalctl" command is owned by "root"."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260505r958566_rule", "$stig_result", "find /usr/bin/journalctl -exec stat -c \"%n %U\" {} \;", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260506r958566_rule: Ubuntu 22.04 LTS must be configured so that the "journalctl" command is group-owned by "root".
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260506r958566_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must be configured so that the "journalctl" command is group-owned by "root"."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify that the "journalctl" command is group-owned by "root" by using the following command: 
 
     $ sudo find /usr/bin/journalctl -exec stat -c "%n %G" {} \; 
     /usr/bin/journalctl root 
 
If "journalctl" is not group-owned by "root", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /usr/bin/journalctl -exec stat -c \"%n %G\" {} \;"
output_0=$(eval "find /usr/bin/journalctl -exec stat -c \"%n %G\" {} \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /usr/bin/journalctl -exec stat -c \"%n %G\" {} \;" "SV-260506r958566_rule")
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
print_rule_result "$rule_result" "SV-260506r958566_rule" "Ubuntu 22.04 LTS must be configured so that the "journalctl" command is group-owned by "root"."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260506r958566_rule", "$stig_result", "find /usr/bin/journalctl -exec stat -c \"%n %G\" {} \;", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260507r991557_rule: Ubuntu 22.04 LTS must configure audit tools to be owned by "root".
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260507r991557_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must configure audit tools to be owned by "root"."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS configures the audit tools to be owned by "root" to prevent any unauthorized access with the following command:  
  
     $ stat -c "%n %U" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules 
     /sbin/auditctl root 
     /sbin/aureport root 
     /sbin/ausearch root 
     /sbin/autrace root 
     /sbin/auditd root 
     /sbin/audispd-zos-remote root 
     /sbin/augenrules root 
 
If any of the audit tools are not owned by "root", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} stat -c \"%n %U\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules"
output_0=$(eval "stat -c \"%n %U\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "stat -c \"%n %U\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules" "SV-260507r991557_rule")
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
print_rule_result "$rule_result" "SV-260507r991557_rule" "Ubuntu 22.04 LTS must configure audit tools to be owned by "root"."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260507r991557_rule", "$stig_result", "stat -c \"%n %U\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260508r958566_rule", "$stig_result", "stat -c \"%n %U\" /var/log", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260509r958566_rule: Ubuntu 22.04 LTS must configure the "/var/log" directory to be group-owned by "syslog".
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260509r958566_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must configure the "/var/log" directory to be group-owned by "syslog"."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that Ubuntu 22.04 LTS configures the "/var/log" directory to be group-owned by "syslog" by using the following command:  
  
     $ stat -c "%n %G" /var/log 
     /var/log syslog  
  
If the "/var/log" directory is not group-owned by "syslog", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} stat -c \"%n %G\" /var/log"
output_0=$(eval "stat -c \"%n %G\" /var/log" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "stat -c \"%n %G\" /var/log" "SV-260509r958566_rule")
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
print_rule_result "$rule_result" "SV-260509r958566_rule" "Ubuntu 22.04 LTS must configure the "/var/log" directory to be group-owned by "syslog"."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260509r958566_rule", "$stig_result", "stat -c \"%n %G\" /var/log", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260510r958566_rule: Ubuntu 22.04 LTS must configure "/var/log/syslog" file to be owned by "syslog".
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260510r958566_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must configure "/var/log/syslog" file to be owned by "syslog"."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that Ubuntu 22.04 LTS configures the "/var/log/syslog" file to be owned by "syslog" by using the following command:  
  
     $ stat -c "%n %U" /var/log/syslog 
     /var/log/syslog  
  
If the "/var/log/syslog" file is not owned by "syslog", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} stat -c \"%n %U\" /var/log/syslog"
output_0=$(eval "stat -c \"%n %U\" /var/log/syslog" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "stat -c \"%n %U\" /var/log/syslog" "SV-260510r958566_rule")
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
print_rule_result "$rule_result" "SV-260510r958566_rule" "Ubuntu 22.04 LTS must configure "/var/log/syslog" file to be owned by "syslog"."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260510r958566_rule", "$stig_result", "stat -c \"%n %U\" /var/log/syslog", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260511r958566_rule: Ubuntu 22.04 LTS must configure the "/var/log/syslog" file to be group-owned by "adm".
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260511r958566_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must configure the "/var/log/syslog" file to be group-owned by "adm"."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that Ubuntu 22.04 LTS configures the "/var/log/syslog" file to be group-owned by "adm" by using the following command:  
  
     $ stat -c "%n %G" /var/log/syslog 
     /var/log/syslog adm  
  
If the "/var/log/syslog" file is not group-owned by "adm", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} stat -c \"%n %G\" /var/log/syslog"
output_0=$(eval "stat -c \"%n %G\" /var/log/syslog" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "stat -c \"%n %G\" /var/log/syslog" "SV-260511r958566_rule")
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
print_rule_result "$rule_result" "SV-260511r958566_rule" "Ubuntu 22.04 LTS must configure the "/var/log/syslog" file to be group-owned by "adm"."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260511r958566_rule", "$stig_result", "stat -c \"%n %G\" /var/log/syslog", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260512r958564_rule: Ubuntu 22.04 LTS must be configured so that the "journalctl" command is not accessible by unauthorized users.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260512r958564_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must be configured so that the "journalctl" command is not accessible by unauthorized users."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify that the "journalctl" command has a permission set of "740" by using the following command: 
 
     $ sudo find /usr/bin/journalctl -exec stat -c "%n %a" {} \; 
     /usr/bin/journalctl 740 
 
If "journalctl" is not set to "740", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} find /usr/bin/journalctl -exec stat -c \"%n %a\" {} \;"
output_0=$(eval "find /usr/bin/journalctl -exec stat -c \"%n %a\" {} \;" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "find /usr/bin/journalctl -exec stat -c \"%n %a\" {} \;" "SV-260512r958564_rule")
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
print_rule_result "$rule_result" "SV-260512r958564_rule" "Ubuntu 22.04 LTS must be configured so that the "journalctl" command is not accessible by unauthorized users."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260512r958564_rule", "$stig_result", "find /usr/bin/journalctl -exec stat -c \"%n %a\" {} \;", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260513r958524_rule", "$stig_result", "find / -type d -perm -002 ! -perm -1000", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260514r958672_rule: Ubuntu 22.04 LTS must have an application firewall installed in order to control remote access methods.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260514r958672_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must have an application firewall installed in order to control remote access methods."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify that the Uncomplicated Firewall is installed by using the following command:  
  
     $ dpkg -l | grep ufw 
     ii     ufw     0.36.1-4ubuntu0.1     all     program for managing a Netfilter firewall 
  
If the "ufw" package is not installed, ask the system administrator if another application firewall is installed.   
  
If no application firewall is installed, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} dpkg -l | grep ufw"
output_0=$(eval "dpkg -l | grep ufw" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "dpkg -l | grep ufw" "SV-260514r958672_rule")
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
print_rule_result "$rule_result" "SV-260514r958672_rule" "Ubuntu 22.04 LTS must have an application firewall installed in order to control remote access methods."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260514r958672_rule", "$stig_result", "dpkg -l | grep ufw", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260515r958672_rule: Ubuntu 22.04 LTS must enable and run the Uncomplicated Firewall (ufw).
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260515r958672_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must enable and run the Uncomplicated Firewall (ufw)."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the ufw is enabled on the system with the following command:  
  
     $ sudo ufw status 
     Status: active 
  
If the above command returns the status as "inactive" or any type of error, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} ufw status"
output_0=$(eval "ufw status" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "ufw status" "SV-260515r958672_rule")
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
print_rule_result "$rule_result" "SV-260515r958672_rule" "Ubuntu 22.04 LTS must enable and run the Uncomplicated Firewall (ufw)."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260515r958672_rule", "$stig_result", "ufw status", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260516r991593_rule: Ubuntu 22.04 LTS must have an application firewall enabled.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260516r991593_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must have an application firewall enabled."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} service\n"

# Check Content:
cat << 'EOF'
Verify the Uncomplicated Firewall (ufw) is enabled on the system with the following command:  
  
     $ systemctl status ufw.service | grep -i "active:" 
     Active: active (exited) since Thu 2022-12-25 00:00:01 NZTD; 365 days 11h ago 
  
If "ufw.service" is "inactive", this is a finding.  
  
If the ufw is not installed, ask the system administrator if another application firewall is installed. If no application firewall is installed, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} systemctl status ufw.service | grep -i \"active:\""
output_0=$(eval "systemctl status ufw.service | grep -i \"active:\"" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "systemctl status ufw.service | grep -i \"active:\"" "SV-260516r991593_rule")
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
print_rule_result "$rule_result" "SV-260516r991593_rule" "Ubuntu 22.04 LTS must have an application firewall enabled."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260516r991593_rule", "$stig_result", "systemctl status ufw.service | grep -i \"active:\"", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260517r958902_rule: Ubuntu 22.04 LTS must configure the Uncomplicated Firewall (ufw) to rate-limit impacted network interfaces.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260517r958902_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must configure the Uncomplicated Firewall (ufw) to rate-limit impacted network interfaces."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify an application firewall is configured to rate limit any connection to the system.  
  
Check all the services listening to the ports by using the following command:  
  
     $ ss -l46ut 
     Netid               State          Recv-Q          Send-Q                               Local Address:Port            Peer Address:Port               Process                 
     tcp                 LISTEN               0                     511                                           *:http                                          *:*  
     tcp                 LISTEN               0                     128                                           [::]:ssh                                        [::]:* 
     tcp                 LISTEN               0                     128                                           [::]:ipp                                        [::]:*  
     tcp                 LISTEN               0                     128                                           [::]:smtp                                    [::]:* 
 
  
For each entry, verify that the ufw is configured to rate limit the service ports by using the following command:  
  
     $ sudo ufw status  
     Status: active  
  
     To                           Action     From  
     --                             ------         ----  
     80/tcp                    LIMIT       Anywhere 
     25/tcp                    LIMIT       Anywhere 
     Anywhere            DENY       240.9.19.81 
     443                           LIMIT      Anywhere        
     22/tcp                     LIMIT      Anywhere     
     80/tcp (v6)            LIMIT      Anywhere 
     25/tcp (v6)            LIMIT      Anywhere                
     22/tcp (v6)            LIMIT      Anywhere (v6)  
 
     25                             DENY OUT    Anywhere 
     25 (v6)                    DENY OUT    Anywhere (v6) 
 
If any port with a state of "LISTEN" that does not have an action of "DENY", is not marked with the "LIMIT" action, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} ss -l46ut"
output_0=$(eval "ss -l46ut" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "ss -l46ut" "SV-260517r958902_rule")
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
echo -e "${BLUE}Executing:${NC} ufw status"
output_1=$(eval "ufw status" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "ufw status" "SV-260517r958902_rule")
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
print_rule_result "$rule_result" "SV-260517r958902_rule" "Ubuntu 22.04 LTS must configure the Uncomplicated Firewall (ufw) to rate-limit impacted network interfaces."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260517r958902_rule", "$stig_result", "ufw status", "$output_1"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260518r958480_rule: Ubuntu 22.04 LTS must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260518r958480_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Check the firewall configuration for any unnecessary or prohibited functions, ports, protocols, and/or services by using the following command: 
  
     $ sudo ufw show raw 
     Chain INPUT (policy ACCEPT 0 packets, 0 bytes)  
          pkts      bytes target     prot opt in     out     source               destination  
  
     Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)  
         pkts      bytes target     prot opt in     out     source               destination  
  
     Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)  
         pkts      bytes target     prot opt in     out     source               destination  
  
Ask the system administrator for the site or program PPSM CLSA. Verify the services allowed by the firewall match the PPSM CLSA.   
  
If there are any additional ports, protocols, or services that are not included in the PPSM CLSA, this is a finding.  
  
If there are any ports, protocols, or services that are prohibited by the PPSM CAL, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} ufw show raw"
output_0=$(eval "ufw show raw" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "ufw show raw" "SV-260518r958480_rule")
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
print_rule_result "$rule_result" "SV-260518r958480_rule" "Ubuntu 22.04 LTS must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260518r958480_rule", "$stig_result", "ufw show raw", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260519r1015004_rule: Ubuntu 22.04 LTS must, for networked systems, compare internal information system clocks at least every 24 hours with a server synchronized to one of the redundant United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DOD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260519r1015004_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must, for networked systems, compare internal information system clocks at least every 24 hours with a server synchronized to one of the redundant United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DOD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS)."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS is configured to compare the system clock at least every 24 hours to the authoritative time source by using the following command: 
 
Note: If the system is not networked, this requirement is not applicable. 
 
     $ sudo grep maxpoll -ir /etc/chrony* 
     server tick.usno.navy.mil iburst maxpoll 16 
  
If the "maxpoll" option is set to a number greater than 16, the line is commented out, or is missing, this is a finding. 
  
Verify that the "chrony.conf" file is configured to an authoritative DOD time source by using the following command:  
  
     $ sudo grep -ir server /etc/chrony* 
     server tick.usno.navy.mil iburst maxpoll 16 
     server tock.usno.navy.mil iburst maxpoll 16 
     server ntp2.usno.navy.mil iburst maxpoll 16 
  
If "server" is not defined, is not set to an authoritative DOD time source, is commented out, or missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep maxpoll -ir /etc/chrony*"
output_0=$(eval "grep maxpoll -ir /etc/chrony*" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep maxpoll -ir /etc/chrony*" "SV-260519r1015004_rule")
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
echo -e "${BLUE}Executing:${NC} grep -ir server /etc/chrony*"
output_1=$(eval "grep -ir server /etc/chrony*" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "grep -ir server /etc/chrony*" "SV-260519r1015004_rule")
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
print_rule_result "$rule_result" "SV-260519r1015004_rule" "Ubuntu 22.04 LTS must, for networked systems, compare internal information system clocks at least every 24 hours with a server synchronized to one of the redundant United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DOD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS)."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260519r1015004_rule", "$stig_result", "grep -ir server /etc/chrony*", "$output_1"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260520r1015005_rule: Ubuntu 22.04 LTS must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260520r1015005_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS synchronizes internal system clocks to the authoritative time source when the time difference is greater than one second.  
 
Note: If the system is not networked, this requirement is not applicable. 
 
Check the value of "makestep" by using the following command:  
  
     $ grep -ir makestep /etc/chrony* 
     makestep 1 1 
 
If "makestep" is not set to "1 1", is commented out, or is missing, this is a finding. 
 
Verify the NTP service is active and the system clock is synchronized with the authoritative time source: 
 
     $ timedatectl | grep -Ei '(synchronized|service)' 
     System clock synchronized: yes 
     NTP service: active 
 
If the NTP service is not active, this is a finding.

If the system clock is not synchronized, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -ir makestep /etc/chrony*"
output_0=$(eval "grep -ir makestep /etc/chrony*" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -ir makestep /etc/chrony*" "SV-260520r1015005_rule")
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
echo -e "${BLUE}Executing:${NC} timedatectl | grep -Ei '(synchronized|service)'"
output_1=$(eval "timedatectl | grep -Ei '(synchronized|service)'" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "timedatectl | grep -Ei '(synchronized|service)'" "SV-260520r1015005_rule")
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
print_rule_result "$rule_result" "SV-260520r1015005_rule" "Ubuntu 22.04 LTS must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260520r1015005_rule", "$stig_result", "timedatectl | grep -Ei '(synchronized|service)'", "$output_1"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260521r958788_rule: Ubuntu 22.04 LTS must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC).
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260521r958788_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC)."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify the time zone is configured to use UTC by using the following command:  
  
     $ timedatectl status | grep -i "time zone" 
     Time zone: Etc/UTC (UTC, +0000) 
  
If "Time zone" is not set to UTC, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} timedatectl status | grep -i \"time zone\""
output_0=$(eval "timedatectl status | grep -i \"time zone\"" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "timedatectl status | grep -i \"time zone\"" "SV-260521r958788_rule")
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
print_rule_result "$rule_result" "SV-260521r958788_rule" "Ubuntu 22.04 LTS must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC)."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260521r958788_rule", "$stig_result", "timedatectl status | grep -i \"time zone\"", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260522r958528_rule: Ubuntu 22.04 LTS must be configured to use TCP syncookies.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260522r958528_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must be configured to use TCP syncookies."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS is configured to use TCP syncookies by using the following command: 
 
     $ sysctl net.ipv4.tcp_syncookies 
     net.ipv4.tcp_syncookies = 1 
 
If the value is not "1", this is a finding. 
  
Check the saved value of TCP syncookies by using the following command:  
  
     $ sudo grep -ir net.ipv4.tcp_syncookies /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2> /dev/null 
 
If the "net.ipv4.tcp_syncookies" option is not set to "1", is commented out, or is missing, this is a finding. 
 
If conflicting results are returned, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} sysctl net.ipv4.tcp_syncookies"
output_0=$(eval "sysctl net.ipv4.tcp_syncookies" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "sysctl net.ipv4.tcp_syncookies" "SV-260522r958528_rule")
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
echo -e "${BLUE}Executing:${NC} grep -ir net.ipv4.tcp_syncookies /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2> /dev/null"
output_1=$(eval "grep -ir net.ipv4.tcp_syncookies /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2> /dev/null" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "grep -ir net.ipv4.tcp_syncookies /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2> /dev/null" "SV-260522r958528_rule")
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
print_rule_result "$rule_result" "SV-260522r958528_rule" "Ubuntu 22.04 LTS must be configured to use TCP syncookies."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260522r958528_rule", "$stig_result", "grep -ir net.ipv4.tcp_syncookies /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2> /dev/null", "$output_1"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260523r958908_rule: Ubuntu 22.04 LTS must have SSH installed.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260523r958908_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must have SSH installed."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify the SSH package is installed by using the following command:  
  
     $ sudo dpkg -l | grep openssh 
     ii     openssh-client     1:8.9p1-3ubuntu0.4     amd64     secure shell (SSH) client, for secure access to remote machines 
     ii  openssh-server     1:8.9p1-3ubuntu0.4     amd64     secure shell (SSH) server, for secure access from remote machines 
     ii  openssh-sftp-server     1:8.9p1-3ubuntu0.4     amd64     secure shell (SSH) sftp server module, for SFTP access from remote machines  
 
If the "openssh" server package is not installed, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} dpkg -l | grep openssh"
output_0=$(eval "dpkg -l | grep openssh" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "dpkg -l | grep openssh" "SV-260523r958908_rule")
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
print_rule_result "$rule_result" "SV-260523r958908_rule" "Ubuntu 22.04 LTS must have SSH installed."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260523r958908_rule", "$stig_result", "dpkg -l | grep openssh", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260524r958908_rule: Ubuntu 22.04 LTS must use SSH to protect the confidentiality and integrity of transmitted information.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260524r958908_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must use SSH to protect the confidentiality and integrity of transmitted information."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} service\n"

# Check Content:
cat << 'EOF'
Verify the "ssh.service" is enabled and active by using the following commands:  
  
     $ sudo systemctl is-enabled ssh 
     enabled 
 
     $ sudo systemctl is-active ssh 
     active 
 
If "ssh.service" is not enabled and active, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} systemctl is-enabled ssh"
output_0=$(eval "systemctl is-enabled ssh" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "systemctl is-enabled ssh" "SV-260524r958908_rule")
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
echo -e "${BLUE}Executing:${NC} systemctl is-active ssh"
output_1=$(eval "systemctl is-active ssh" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "systemctl is-active ssh" "SV-260524r958908_rule")
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
print_rule_result "$rule_result" "SV-260524r958908_rule" "Ubuntu 22.04 LTS must use SSH to protect the confidentiality and integrity of transmitted information."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260524r958908_rule", "$stig_result", "systemctl is-active ssh", "$output_1"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260525r958390_rule: Ubuntu 22.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting any local or remote connection to the system.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260525r958390_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting any local or remote connection to the system."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS displays the Standard Mandatory DOD Notice and Consent Banner before granting access to Ubuntu 22.04 LTS via an SSH logon by using the following command:  
  
     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'banner' 
     /etc/ssh/sshd_config:Banner /etc/issue.net 
  
The command will return the banner option along with the name of the file that contains the SSH banner. If the line is commented out, missing, or conflicting results are returned, this is a finding. 
  
Verify the specified banner file matches the Standard Mandatory DOD Notice and Consent Banner exactly:  
  
     $ cat /etc/issue.net  
     You are accessing a U.S. Government (USG) Information System (IS) that is 
     provided for USG-authorized use only. By using this IS (which includes any 
     device attached to this IS), you consent to the following conditions: 
     -The USG routinely intercepts and monitors communications on this IS for 
     purposes including, but not limited to, penetration testing, COMSEC monitoring, 
     network operations and defense, personnel misconduct (PM), law enforcement 
     (LE), and counterintelligence (CI) investigations. 
     -At any time, the USG may inspect and seize data stored on this IS. 
     -Communications using, or data stored on, this IS are not private, are subject 
     to routine monitoring, interception, and search, and may be disclosed or used 
     for any USG-authorized purpose. 
     -This IS includes security measures (e.g., authentication and access controls) 
     to protect USG interests--not for your personal benefit or privacy. 
     -Notwithstanding the above, using this IS does not constitute consent to PM, LE 
     or CI investigative searching or monitoring of the content of privileged 
     communications, or work product, related to personal representation or services 
     by attorneys, psychotherapists, or clergy, and their assistants. Such 
     communications and work product are private and confidential. See User 
     Agreement for details. 
 
If the banner text does not match the Standard Mandatory DOD Notice and Consent Banner exactly, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} cat /etc/issue.net"
output_0=$(eval "cat /etc/issue.net" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "cat /etc/issue.net" "SV-260525r958390_rule")
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
print_rule_result "$rule_result" "SV-260525r958390_rule" "Ubuntu 22.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting any local or remote connection to the system."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260525r958390_rule", "$stig_result", "cat /etc/issue.net", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260526r991591_rule: Ubuntu 22.04 LTS must not allow unattended or automatic login via SSH.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260526r991591_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must not allow unattended or automatic login via SSH."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that unattended or automatic login via SSH is disabled by using the following command: 
 
     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iEH '(permit(.*?)(passwords|environment))' 
     /etc/ssh/sshd_config:PermitEmptyPasswords no 
     /etc/ssh/sshd_config:PermitUserEnvironment no 
 
If "PermitEmptyPasswords" and "PermitUserEnvironment" are not set to "no", are commented out, are missing, or conflicting results are returned, this is a finding.
EOF

echo ""


echo -e "${YELLOW}[MANUAL]${NC} No automated commands available for this check."
result="MANUAL"
update_counters "$result"
echo -e "${YELLOW}[MANUAL]${NC} SV-260526r991591_rule: Ubuntu 22.04 LTS must not allow unattended or automatic login via SSH."

# --------------------------------------------------------------------------------
# Check for SV-260527r986275_rule: Ubuntu 22.04 LTS must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260527r986275_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify the SSH server automatically terminates a user session after the SSH client has become unresponsive by using the following command:  
 
     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'clientalivecountmax' 
     /etc/ssh/sshd_config:ClientAliveCountMax 1 
 
If "ClientAliveCountMax" is not to "1", if conflicting results are returned, is commented out, or is missing, this is a finding.
EOF

echo ""


echo -e "${YELLOW}[MANUAL]${NC} No automated commands available for this check."
result="MANUAL"
update_counters "$result"
echo -e "${YELLOW}[MANUAL]${NC} SV-260527r986275_rule: Ubuntu 22.04 LTS must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive."

# --------------------------------------------------------------------------------
# Check for SV-260528r970703_rule: Ubuntu 22.04 LTS must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260528r970703_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify the SSH server automatically terminates a user session after the SSH client has been unresponsive for 10 minutes by using the following command: 
 
     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'clientaliveinterval' 
     /etc/ssh/sshd_config:ClientAliveInterval 600 
 
If "ClientAliveInterval" does not exist, is not set to a value of "600" or less, if conflicting results are returned, is commented out, or is missing, this is a finding.
EOF

echo ""


echo -e "${YELLOW}[MANUAL]${NC} No automated commands available for this check."
result="MANUAL"
update_counters "$result"
echo -e "${YELLOW}[MANUAL]${NC} SV-260528r970703_rule: Ubuntu 22.04 LTS must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive."

# --------------------------------------------------------------------------------
# Check for SV-260529r991589_rule: Ubuntu 22.04 LTS must be configured so that remote X connections are disabled, unless to fulfill documented and validated mission requirements.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260529r991589_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must be configured so that remote X connections are disabled, unless to fulfill documented and validated mission requirements."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that X11 forwarding is disabled by using the following command:  
 
     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'x11forwarding' 
     /etc/ssh/sshd_config:X11Forwarding no 
  
If "X11Forwarding" is set to "yes" and is not documented with the information system security officer (ISSO) as an operational requirement, is commented out, is missing, or conflicting results are returned, this is a finding.
EOF

echo ""


echo -e "${YELLOW}[MANUAL]${NC} No automated commands available for this check."
result="MANUAL"
update_counters "$result"
echo -e "${YELLOW}[MANUAL]${NC} SV-260529r991589_rule: Ubuntu 22.04 LTS must be configured so that remote X connections are disabled, unless to fulfill documented and validated mission requirements."

# --------------------------------------------------------------------------------
# Check for SV-260530r991589_rule: Ubuntu 22.04 LTS SSH daemon must prevent remote hosts from connecting to the proxy display.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260530r991589_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS SSH daemon must prevent remote hosts from connecting to the proxy display."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify the SSH server prevents remote hosts from connecting to the proxy display by using the following command: 
 
     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'x11uselocalhost' 
     /etc/ssh/sshd_config:X11UseLocalhost yes 
 
If "X11UseLocalhost" is set to "no", is commented out, is missing, or conflicting results are returned, this is a finding.
EOF

echo ""


echo -e "${YELLOW}[MANUAL]${NC} No automated commands available for this check."
result="MANUAL"
update_counters "$result"
echo -e "${YELLOW}[MANUAL]${NC} SV-260530r991589_rule: Ubuntu 22.04 LTS SSH daemon must prevent remote hosts from connecting to the proxy display."

# --------------------------------------------------------------------------------
# Check for SV-260531r958408_rule: Ubuntu 22.04 LTS must configure the SSH daemon to use FIPS 140-3-approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260531r958408_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must configure the SSH daemon to use FIPS 140-3-approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify the SSH server is configured to only implement FIPS-approved ciphers with the following command: 
 
     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'ciphers' 
     /etc/ssh/sshd_config:Ciphers aes256-ctr,aes256-gcm@openssh.com,aes192-ctr,aes128-ctr,aes128-gcm@openssh.com 
  
If "Ciphers" does not contain only the ciphers "aes256-ctr,aes256-gcm@openssh.com,aes192-ctr,aes128-ctr,aes128-gcm@openssh.com" in exact order, is commented out, is missing, or conflicting results are returned, this is a finding.
EOF

echo ""


echo -e "${YELLOW}[MANUAL]${NC} No automated commands available for this check."
result="MANUAL"
update_counters "$result"
echo -e "${YELLOW}[MANUAL]${NC} SV-260531r958408_rule: Ubuntu 22.04 LTS must configure the SSH daemon to use FIPS 140-3-approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission."

# --------------------------------------------------------------------------------
# Check for SV-260532r991554_rule: Ubuntu 22.04 LTS must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-3-approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260532r991554_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-3-approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to information during transmission."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify the SSH server is configured to only use MACs that employ FIPS 140-3 approved ciphers by using the following command: 
 
     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'macs' 
     /etc/ssh/sshd_config:MACs hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-256-etm@openssh.com 
 
If "MACs" does not contain only the hashes "hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-256-etm@openssh.com" in exact order, is commented out, is missing, or conflicting results are returned, this is a finding.
EOF

echo ""


echo -e "${YELLOW}[MANUAL]${NC} No automated commands available for this check."
result="MANUAL"
update_counters "$result"
echo -e "${YELLOW}[MANUAL]${NC} SV-260532r991554_rule: Ubuntu 22.04 LTS must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-3-approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to information during transmission."

# --------------------------------------------------------------------------------
# Check for SV-260533r958408_rule: Ubuntu 22.04 LTS SSH server must be configured to use only FIPS-validated key exchange algorithms.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260533r958408_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS SSH server must be configured to use only FIPS-validated key exchange algorithms."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that the SSH server is configured to use only FIPS-validated key exchange algorithms by using the following command: 
 
     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'kexalgorithms' 
     /etc/ssh/sshd_config:KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256 
  
If "KexAlgorithms" does not contain only the algorithms "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256" in exact order, is commented out, is missing, or conflicting results are returned, this is a finding.
EOF

echo ""


echo -e "${YELLOW}[MANUAL]${NC} No automated commands available for this check."
result="MANUAL"
update_counters "$result"
echo -e "${YELLOW}[MANUAL]${NC} SV-260533r958408_rule: Ubuntu 22.04 LTS SSH server must be configured to use only FIPS-validated key exchange algorithms."

# --------------------------------------------------------------------------------
# Check for SV-260534r958510_rule: Ubuntu 22.04 LTS must use strong authenticators in establishing nonlocal maintenance and diagnostic sessions.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260534r958510_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must use strong authenticators in establishing nonlocal maintenance and diagnostic sessions."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS is configured to use strong authenticators in the establishment of nonlocal maintenance and diagnostic maintenance by using the following command: 
 
     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'usepam' 
     /etc/ssh/sshd_config:UsePAM yes 
 
If "UsePAM" is not set to "yes", is commented out, is missing, or conflicting results are returned, this is a finding.
EOF

echo ""


echo -e "${YELLOW}[MANUAL]${NC} No automated commands available for this check."
result="MANUAL"
update_counters "$result"
echo -e "${YELLOW}[MANUAL]${NC} SV-260534r958510_rule: Ubuntu 22.04 LTS must use strong authenticators in establishing nonlocal maintenance and diagnostic sessions."

# --------------------------------------------------------------------------------
# Check for SV-260535r958390_rule: Ubuntu 22.04 LTS must enable the graphical user logon banner to display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260535r958390_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must enable the graphical user logon banner to display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS is configured to display the Standard Mandatory DOD Notice and Consent Banner before granting access to the operating system via a graphical user logon by using the following command:  
  
Note: If no graphical user interface is installed, this requirement is not applicable. 
  
     $ grep -i banner-message-enable /etc/gdm3/greeter.dconf-defaults 
     banner-message-enable=true  
  
If the value for "banner-message-enable" is set to "false", the line is commented out, or no value is returned, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i banner-message-enable /etc/gdm3/greeter.dconf-defaults"
output_0=$(eval "grep -i banner-message-enable /etc/gdm3/greeter.dconf-defaults" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i banner-message-enable /etc/gdm3/greeter.dconf-defaults" "SV-260535r958390_rule")
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
print_rule_result "$rule_result" "SV-260535r958390_rule" "Ubuntu 22.04 LTS must enable the graphical user logon banner to display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260535r958390_rule", "$stig_result", "grep -i banner-message-enable /etc/gdm3/greeter.dconf-defaults", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260536r958390_rule: Ubuntu 22.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260536r958390_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS displays the Standard Mandatory DOD Notice and Consent Banner before granting access to the operating system via a graphical user logon with the command:  
  
Note: If no graphical user interface is installed, this requirement is not applicable. 
  
     $ grep -i banner-message-text /etc/gdm3/greeter.dconf-defaults 
  
banner-message-text="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\n\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n\n-At any time, the USG may inspect and seize data stored on this IS.\n\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." 
  
If the banner-message-text is missing, commented out, or does not match the Standard Mandatory DOD Notice and Consent Banner exactly, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i banner-message-text /etc/gdm3/greeter.dconf-defaults"
output_0=$(eval "grep -i banner-message-text /etc/gdm3/greeter.dconf-defaults" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i banner-message-text /etc/gdm3/greeter.dconf-defaults" "SV-260536r958390_rule")
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
print_rule_result "$rule_result" "SV-260536r958390_rule" "Ubuntu 22.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260536r958390_rule", "$stig_result", "grep -i banner-message-text /etc/gdm3/greeter.dconf-defaults", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260537r958400_rule: Ubuntu 22.04 LTS must retain a user's session lock until that user reestablishes access using established identification and authentication procedures.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260537r958400_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must retain a user's session lock until that user reestablishes access using established identification and authentication procedures."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS has a graphical user interface session lock enabled by using the following command: 
  
Note: If no graphical user interface is installed, this requirement is not applicable. 
  
     $ sudo gsettings get org.gnome.desktop.screensaver lock-enabled 
     true 
  
If "lock-enabled" is not set to "true", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} gsettings get org.gnome.desktop.screensaver lock-enabled"
output_0=$(eval "gsettings get org.gnome.desktop.screensaver lock-enabled" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "gsettings get org.gnome.desktop.screensaver lock-enabled" "SV-260537r958400_rule")
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
print_rule_result "$rule_result" "SV-260537r958400_rule" "Ubuntu 22.04 LTS must retain a user's session lock until that user reestablishes access using established identification and authentication procedures."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260537r958400_rule", "$stig_result", "gsettings get org.gnome.desktop.screensaver lock-enabled", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260538r958402_rule: Ubuntu 22.04 LTS must initiate a graphical session lock after 15 minutes of inactivity.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260538r958402_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must initiate a graphical session lock after 15 minutes of inactivity."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS has a graphical user interface session lock configured to activate after 15 minutes of inactivity by using the following commands:   
  
Note: If no graphical user interface is installed, this requirement is not applicable. 
 
Get the following settings to verify the graphical user interface session is configured to lock the graphical user session after 15 minutes of inactivity:  
   
     $ gsettings get org.gnome.desktop.screensaver lock-enabled 
     true 
 
     $ gsettings get org.gnome.desktop.screensaver lock-delay 
     uint32 0 
 
     $ gsettings get org.gnome.desktop.session idle-delay 
     uint32 900 
 
If "lock-enabled" is not set to "true", is commented out, or is missing, this is a finding. 
 
If "lock-delay" is set to a value greater than "0", or if "idle-delay" is set to a value greater than "900", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} gsettings get org.gnome.desktop.screensaver lock-enabled"
output_0=$(eval "gsettings get org.gnome.desktop.screensaver lock-enabled" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "gsettings get org.gnome.desktop.screensaver lock-enabled" "SV-260538r958402_rule")
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
echo -e "${BLUE}Executing:${NC} gsettings get org.gnome.desktop.screensaver lock-delay"
output_1=$(eval "gsettings get org.gnome.desktop.screensaver lock-delay" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "gsettings get org.gnome.desktop.screensaver lock-delay" "SV-260538r958402_rule")
echo -e "${BLUE}Command 2 Result:${NC} $cmd_result_1"

# If any command fails, the whole rule fails
if [ "$cmd_result_1" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_1" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_1" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Command 3
echo -e "${BLUE}Executing:${NC} gsettings get org.gnome.desktop.session idle-delay"
output_2=$(eval "gsettings get org.gnome.desktop.session idle-delay" 2>&1)
exit_code_2=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_2"
echo -e "${BLUE}Output:${NC}"
echo "$output_2"
echo ""

# Evaluate command result using function
cmd_result_2=$(evaluate_command_result "$exit_code_2" "$output_2" "positive" "gsettings get org.gnome.desktop.session idle-delay" "SV-260538r958402_rule")
echo -e "${BLUE}Command 3 Result:${NC} $cmd_result_2"

# If any command fails, the whole rule fails
if [ "$cmd_result_2" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_2" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_2" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-260538r958402_rule" "Ubuntu 22.04 LTS must initiate a graphical session lock after 15 minutes of inactivity."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260538r958402_rule", "$stig_result", "gsettings get org.gnome.desktop.session idle-delay", "$output_2"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260539r991589_rule: Ubuntu 22.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence if a graphical user interface is installed.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260539r991589_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence if a graphical user interface is installed."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS is not configured to reboot the system when Ctrl-Alt-Delete is pressed when using a graphical user interface by using the following command: 
 
Note: If no graphical user interface is installed, this requirement is not applicable. 
 
     $ gsettings get org.gnome.settings-daemon.plugins.media-keys logout 
     @as [] 
 
If the "logout" key is bound to an action, is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} gsettings get org.gnome.settings-daemon.plugins.media-keys logout"
output_0=$(eval "gsettings get org.gnome.settings-daemon.plugins.media-keys logout" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "gsettings get org.gnome.settings-daemon.plugins.media-keys logout" "SV-260539r991589_rule")
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
print_rule_result "$rule_result" "SV-260539r991589_rule" "Ubuntu 22.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence if a graphical user interface is installed."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260539r991589_rule", "$stig_result", "gsettings get org.gnome.settings-daemon.plugins.media-keys logout", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260540r986276_rule: Ubuntu 22.04 LTS must disable automatic mounting of Universal Serial Bus (USB) mass storage driver.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260540r986276_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must disable automatic mounting of Universal Serial Bus (USB) mass storage driver."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS disables ability to load the USB storage kernel module by using the following command: 
 
     $ grep usb-storage /etc/modprobe.d/* | grep "/bin/false" 
     /etc/modprobe.d/stig.conf:install usb-storage /bin/false 
 
If the command does not return any output, or the line is commented out, this is a finding. 
 
Verify Ubuntu 22.04 LTS disables the ability to use USB mass storage device. 
 
     $ grep usb-storage /etc/modprobe.d/* | grep -i "blacklist" 
     /etc/modprobe.d/stig.conf:blacklist usb-storage 
 
If the command does not return any output, or the line is commented out, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep usb-storage /etc/modprobe.d/* | grep \"/bin/false\""
output_0=$(eval "grep usb-storage /etc/modprobe.d/* | grep \"/bin/false\"" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep usb-storage /etc/modprobe.d/* | grep \"/bin/false\"" "SV-260540r986276_rule")
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
echo -e "${BLUE}Executing:${NC} grep usb-storage /etc/modprobe.d/* | grep -i \"blacklist\""
output_1=$(eval "grep usb-storage /etc/modprobe.d/* | grep -i \"blacklist\"" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "grep usb-storage /etc/modprobe.d/* | grep -i \"blacklist\"" "SV-260540r986276_rule")
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
print_rule_result "$rule_result" "SV-260540r986276_rule" "Ubuntu 22.04 LTS must disable automatic mounting of Universal Serial Bus (USB) mass storage driver."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260540r986276_rule", "$stig_result", "grep usb-storage /etc/modprobe.d/* | grep -i \"blacklist\"", "$output_1"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260541r958358_rule: Ubuntu 22.04 LTS must disable all wireless network adapters.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260541r958358_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must disable all wireless network adapters."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that there are no wireless interfaces configured on the system by using the following command:  
 
Note: If the system does not have any physical wireless network radios, this requirement is not applicable.  
  
     $ cat /proc/net/wireless 
  
If any wireless interface names are listed under "Interface" and have not been documented and approved by the information system security officer (ISSO), this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} cat /proc/net/wireless"
output_0=$(eval "cat /proc/net/wireless" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "cat /proc/net/wireless" "SV-260541r958358_rule")
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
print_rule_result "$rule_result" "SV-260541r958358_rule" "Ubuntu 22.04 LTS must disable all wireless network adapters."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260541r958358_rule", "$stig_result", "cat /proc/net/wireless", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260542r1015006_rule", "$stig_result", "passwd -S root", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260543r958482_rule", "$stig_result", "awk -F \":\" 'list[\$3]++{print \$1, \$3}' /etc/passwd", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260545r1015007_rule", "$stig_result", "grep -i pass_min_days /etc/login.defs", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260546r1015008_rule: Ubuntu 22.04 LTS must enforce a 60-day maximum password lifetime restriction. Passwords for new users must have a 60-day maximum password lifetime restriction.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260546r1015008_rule ===${NC}"
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i pass_max_days /etc/login.defs" "SV-260546r1015008_rule")
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
print_rule_result "$rule_result" "SV-260546r1015008_rule" "Ubuntu 22.04 LTS must enforce a 60-day maximum password lifetime restriction. Passwords for new users must have a 60-day maximum password lifetime restriction."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260546r1015008_rule", "$stig_result", "grep -i pass_max_days /etc/login.defs", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260547r1015009_rule", "$stig_result", "grep INACTIVE /etc/default/useradd", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260548r958364_rule", "$stig_result", "chage -l  | grep -E '(Password|Account) expires'", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260549r958388_rule: Ubuntu 22.04 LTS must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts have been made.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260549r958388_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts have been made."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that Ubuntu 22.04 LTS utilizes the "pam_faillock" module by using the following command: 
 
     $ grep faillock /etc/pam.d/common-auth 
 
auth     [default=die]  pam_faillock.so authfail 
auth     sufficient     pam_faillock.so authsucc 
 
If the "pam_faillock.so" module is not present in the "/etc/pam.d/common-auth" file, this is a finding. 
 
Verify the "pam_faillock" module is configured to use the following options: 
 
     $ sudo grep -Ew 'silent|audit|deny|fail_interval|unlock_time' /etc/security/faillock.conf 
     audit 
     silent 
     deny = 3 
     fail_interval = 900 
     unlock_time = 0 
 
If "audit" is commented out, or is missing, this is a finding.

If "silent" is commented out, or is missing, this is a finding.

If "deny" is set to a value greater than "3", is commented out, or is missing, this is a finding.
 
If "fail_interval" is set to a value greater than "900", is commented out, or is missing, this is a finding.
 
If "unlock_time" is not set to "0", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep faillock /etc/pam.d/common-auth"
output_0=$(eval "grep faillock /etc/pam.d/common-auth" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep faillock /etc/pam.d/common-auth" "SV-260549r958388_rule")
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
echo -e "${BLUE}Executing:${NC} grep -Ew 'silent|audit|deny|fail_interval|unlock_time' /etc/security/faillock.conf"
output_1=$(eval "grep -Ew 'silent|audit|deny|fail_interval|unlock_time' /etc/security/faillock.conf" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "grep -Ew 'silent|audit|deny|fail_interval|unlock_time' /etc/security/faillock.conf" "SV-260549r958388_rule")
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
print_rule_result "$rule_result" "SV-260549r958388_rule" "Ubuntu 22.04 LTS must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts have been made."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260549r958388_rule", "$stig_result", "grep -Ew 'silent|audit|deny|fail_interval|unlock_time' /etc/security/faillock.conf", "$output_1"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260550r991588_rule: Ubuntu 22.04 LTS must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260550r991588_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must enforce a delay of at least four seconds between logon prompts following a failed logon attempt."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS enforces a delay of at least four seconds between logon prompts following a failed logon attempt by using the following command:  
  
     $ grep pam_faildelay /etc/pam.d/common-auth 
     auth     required     pam_faildelay.so     delay=4000000  
  
If "delay" is not set to "4000000" or greater, the line is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep pam_faildelay /etc/pam.d/common-auth"
output_0=$(eval "grep pam_faildelay /etc/pam.d/common-auth" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep pam_faildelay /etc/pam.d/common-auth" "SV-260550r991588_rule")
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
print_rule_result "$rule_result" "SV-260550r991588_rule" "Ubuntu 22.04 LTS must enforce a delay of at least four seconds between logon prompts following a failed logon attempt."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260550r991588_rule", "$stig_result", "grep pam_faildelay /etc/pam.d/common-auth", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260551r991589_rule: Ubuntu 22.04 LTS must display the date and time of the last successful account logon upon logon.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260551r991589_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must display the date and time of the last successful account logon upon logon."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify users are provided with feedback on when account accesses last occurred by using the following command:  
  
     $ grep pam_lastlog /etc/pam.d/login 
     session     required     pam_lastlog.so     showfailed 
  
If the line containing "pam_lastlog" is not set to "required", or the "silent" option is present, the "showfailed" option is missing, the line is commented out, or the line is missing , this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep pam_lastlog /etc/pam.d/login"
output_0=$(eval "grep pam_lastlog /etc/pam.d/login" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep pam_lastlog /etc/pam.d/login" "SV-260551r991589_rule")
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
print_rule_result "$rule_result" "SV-260551r991589_rule" "Ubuntu 22.04 LTS must display the date and time of the last successful account logon upon logon."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260551r991589_rule", "$stig_result", "grep pam_lastlog /etc/pam.d/login", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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
echo -e "${BLUE}Executing:${NC} grep -r -s '^[^"
output_0=$(eval "grep -r -s '^[^" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -r -s '^[^" "SV-260552r958398_rule")
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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260552r958398_rule", "$stig_result", "grep -r -s '^[^", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260553r1015010_rule", "$stig_result", "dpkg -l | grep vlock", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260554r958636_rule", "$stig_result", "grep -E \"\bTMOUT=[0-9]+\" /etc/bash.bashrc /etc/profile.d/*", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260555r991590_rule: Ubuntu 22.04 LTS default filesystem permissions must be defined in such a way that all authenticated users can read and modify only their own files.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260555r991590_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS default filesystem permissions must be defined in such a way that all authenticated users can read and modify only their own files."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS defines default permissions for all authenticated users in such a way that the user can read and modify only their own files by using the following command: 
  
     $ grep -i '^\s*umask' /etc/login.defs  
     UMASK 077  
  
If the "UMASK" variable is set to "000", this is a finding with the severity raised to a CAT I.

If "UMASK" is not set to "077", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i '^\s*umask' /etc/login.defs"
output_0=$(eval "grep -i '^\s*umask' /etc/login.defs" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i '^\s*umask' /etc/login.defs" "SV-260555r991590_rule")
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
print_rule_result "$rule_result" "SV-260555r991590_rule" "Ubuntu 22.04 LTS default filesystem permissions must be defined in such a way that all authenticated users can read and modify only their own files."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260555r991590_rule", "$stig_result", "grep -i '^\s*umask' /etc/login.defs", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260556r958702_rule: Ubuntu 22.04 LTS must have the "apparmor" package installed.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260556r958702_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must have the "apparmor" package installed."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS has the "apparmor" package installed by using the following command: 
  
     $ dpkg -l | grep apparmor  
     ii     apparmor     3.0.4-2ubuntu2.3     amd64     user-space parser utility for AppArmor 
 
If the "apparmor" package is not installed, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} dpkg -l | grep apparmor"
output_0=$(eval "dpkg -l | grep apparmor" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "dpkg -l | grep apparmor" "SV-260556r958702_rule")
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
print_rule_result "$rule_result" "SV-260556r958702_rule" "Ubuntu 22.04 LTS must have the "apparmor" package installed."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260556r958702_rule", "$stig_result", "dpkg -l | grep apparmor", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260557r958804_rule: Ubuntu 22.04 LTS must be configured to use AppArmor.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260557r958804_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must be configured to use AppArmor."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} service\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS AppArmor is active by using the following commands:  
 
     $ systemctl is-enabled apparmor.service 
     enabled  
 
     $ systemctl is-active apparmor.service 
     active   
 
If "apparmor.service" is not enabled and active, this is a finding. 
 
Check if AppArmor profiles are loaded and enforced by using the following command: 
 
     $ sudo apparmor_status | grep -i profile 
     32 profiles are loaded. 
     32 profiles are in enforce mode. 
     0 profiles are in complain mode. 
     0 profiles are in kill mode. 
     0 profiles are in unconfined mode. 
     2 processes have profiles defined. 
     0 processes are unconfined but have a profile defined. 
 
If no profiles are loaded and enforced, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} systemctl is-enabled apparmor.service"
output_0=$(eval "systemctl is-enabled apparmor.service" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "systemctl is-enabled apparmor.service" "SV-260557r958804_rule")
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
echo -e "${BLUE}Executing:${NC} systemctl is-active apparmor.service"
output_1=$(eval "systemctl is-active apparmor.service" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "systemctl is-active apparmor.service" "SV-260557r958804_rule")
echo -e "${BLUE}Command 2 Result:${NC} $cmd_result_1"

# If any command fails, the whole rule fails
if [ "$cmd_result_1" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_1" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_1" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Command 3
echo -e "${BLUE}Executing:${NC} apparmor_status | grep -i profile"
output_2=$(eval "apparmor_status | grep -i profile" 2>&1)
exit_code_2=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_2"
echo -e "${BLUE}Output:${NC}"
echo "$output_2"
echo ""

# Evaluate command result using function
cmd_result_2=$(evaluate_command_result "$exit_code_2" "$output_2" "positive" "apparmor_status | grep -i profile" "SV-260557r958804_rule")
echo -e "${BLUE}Command 3 Result:${NC} $cmd_result_2"

# If any command fails, the whole rule fails
if [ "$cmd_result_2" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_2" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_2" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-260557r958804_rule" "Ubuntu 22.04 LTS must be configured to use AppArmor."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260557r958804_rule", "$stig_result", "apparmor_status | grep -i profile", "$output_2"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260558r1015011_rule: Ubuntu 22.04 LTS must require users to reauthenticate for privilege escalation or when changing roles.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260558r1015011_rule ===${NC}"
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
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -Ei '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*" "SV-260558r1015011_rule")
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
print_rule_result "$rule_result" "SV-260558r1015011_rule" "Ubuntu 22.04 LTS must require users to reauthenticate for privilege escalation or when changing roles."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260558r1015011_rule", "$stig_result", "grep -Ei '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260559r958518_rule", "$stig_result", "grep sudo /etc/group", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260560r1015012_rule", "$stig_result", "grep -i ucredit /etc/security/pwquality.conf", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260561r1015013_rule", "$stig_result", "grep -i lcredit /etc/security/pwquality.conf", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260562r1015014_rule", "$stig_result", "grep -i dcredit /etc/security/pwquality.conf", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260563r1015015_rule", "$stig_result", "grep -i ocredit /etc/security/pwquality.conf", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260564r991587_rule", "$stig_result", "grep -i dictcheck /etc/security/pwquality.conf", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260565r1015016_rule", "$stig_result", "grep -i minlen /etc/security/pwquality.conf", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260566r1015017_rule", "$stig_result", "grep -i difok /etc/security/pwquality.conf", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260567r991587_rule: Ubuntu 22.04 LTS must be configured so that when passwords are changed or new passwords are established, pwquality must be used.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260567r991587_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must be configured so that when passwords are changed or new passwords are established, pwquality must be used."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS enforces password complexity rules by using the following command:   
 
     $ grep -i enforcing /etc/security/pwquality.conf  
     enforcing = 1  
  
If "enforcing" is not "1", is commented out, or is missing, this is a finding.  
  
Check for the use of "pwquality" by using the following command:  
  
     $ cat /etc/pam.d/common-password | grep requisite | grep pam_pwquality 
      password     requisite     pam_pwquality.so retry=3  
  
If "retry" is set to "0" or is greater than "3", or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i enforcing /etc/security/pwquality.conf"
output_0=$(eval "grep -i enforcing /etc/security/pwquality.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i enforcing /etc/security/pwquality.conf" "SV-260567r991587_rule")
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
echo -e "${BLUE}Executing:${NC} cat /etc/pam.d/common-password | grep requisite | grep pam_pwquality"
output_1=$(eval "cat /etc/pam.d/common-password | grep requisite | grep pam_pwquality" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "cat /etc/pam.d/common-password | grep requisite | grep pam_pwquality" "SV-260567r991587_rule")
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
print_rule_result "$rule_result" "SV-260567r991587_rule" "Ubuntu 22.04 LTS must be configured so that when passwords are changed or new passwords are established, pwquality must be used."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260567r991587_rule", "$stig_result", "cat /etc/pam.d/common-password | grep requisite | grep pam_pwquality", "$output_1"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260569r1015018_rule: Ubuntu 22.04 LTS must store only encrypted representations of passwords.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260569r1015018_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must store only encrypted representations of passwords."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify the Ubuntu operating stores only encrypted representations of passwords with the following command: 
 
     $ grep pam_unix.so /etc/pam.d/common-password 
     password [success=1 default=ignore] pam_unix.so obscure sha512 shadow remember=5 rounds=5000 
 
If "sha512" is missing from the "pam_unix.so" line, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep pam_unix.so /etc/pam.d/common-password"
output_0=$(eval "grep pam_unix.so /etc/pam.d/common-password" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep pam_unix.so /etc/pam.d/common-password" "SV-260569r1015018_rule")
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
print_rule_result "$rule_result" "SV-260569r1015018_rule" "Ubuntu 22.04 LTS must store only encrypted representations of passwords."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260569r1015018_rule", "$stig_result", "grep pam_unix.so /etc/pam.d/common-password", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260570r991589_rule: Ubuntu 22.04 LTS must not allow accounts configured with blank or null passwords.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260570r991589_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must not allow accounts configured with blank or null passwords."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
To verify that null passwords cannot be used, run the following command:  
 
     $ grep nullok /etc/pam.d/common-password 
 
If this produces any output, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep nullok /etc/pam.d/common-password"
output_0=$(eval "grep nullok /etc/pam.d/common-password" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep nullok /etc/pam.d/common-password" "SV-260570r991589_rule")
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
print_rule_result "$rule_result" "SV-260570r991589_rule" "Ubuntu 22.04 LTS must not allow accounts configured with blank or null passwords."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260570r991589_rule", "$stig_result", "grep nullok /etc/pam.d/common-password", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260571r991589_rule", "$stig_result", "awk -F: '!\$2 {print \$1}' /etc/shadow", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260572r971535_rule: Ubuntu 22.04 LTS must encrypt all stored passwords with a FIPS 140-3-approved cryptographic hashing algorithm.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260572r971535_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must encrypt all stored passwords with a FIPS 140-3-approved cryptographic hashing algorithm."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that the shadow password suite configuration is set to encrypt passwords with a FIPS 140-3 approved cryptographic hashing algorithm by using the following command:  
  
     $ grep -i '^\s*encrypt_method' /etc/login.defs 
     ENCRYPT_METHOD SHA512  
  
If "ENCRYPT_METHOD" does not equal SHA512 or greater, is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i '^\s*encrypt_method' /etc/login.defs"
output_0=$(eval "grep -i '^\s*encrypt_method' /etc/login.defs" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i '^\s*encrypt_method' /etc/login.defs" "SV-260572r971535_rule")
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
print_rule_result "$rule_result" "SV-260572r971535_rule" "Ubuntu 22.04 LTS must encrypt all stored passwords with a FIPS 140-3-approved cryptographic hashing algorithm."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260572r971535_rule", "$stig_result", "grep -i '^\s*encrypt_method' /etc/login.defs", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260573r1015019_rule: Ubuntu 22.04 LTS must implement multifactor authentication for remote access to privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260573r1015019_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must implement multifactor authentication for remote access to privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS has the packages required for multifactor authentication installed by using the following command:  
 
     $ dpkg -l | grep libpam-pkcs11 
     ii     libpam-pkcs11     0.6.11-4build2     amd64     Fully featured PAM module for using PKCS#11 smart cards 
 
If the "libpam-pkcs11" package is not installed, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} dpkg -l | grep libpam-pkcs11"
output_0=$(eval "dpkg -l | grep libpam-pkcs11" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "dpkg -l | grep libpam-pkcs11" "SV-260573r1015019_rule")
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
print_rule_result "$rule_result" "SV-260573r1015019_rule" "Ubuntu 22.04 LTS must implement multifactor authentication for remote access to privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260573r1015019_rule", "$stig_result", "dpkg -l | grep libpam-pkcs11", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260574r958816_rule: Ubuntu 22.04 LTS must accept personal identity verification (PIV) credentials.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260574r958816_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must accept personal identity verification (PIV) credentials."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify the "opensc-pcks11" package is installed on the system by using the following command:  
  
     $ dpkg -l | grep opensc-pkcs11 
     ii     opensc-pkcs11:amd64     0.22.0-1Ubuntu2     amd64     Smart card utilities with support for PKCS#15 compatible cards  
  
If the "opensc-pcks11" package is not installed, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} dpkg -l | grep opensc-pkcs11"
output_0=$(eval "dpkg -l | grep opensc-pkcs11" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "dpkg -l | grep opensc-pkcs11" "SV-260574r958816_rule")
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
print_rule_result "$rule_result" "SV-260574r958816_rule" "Ubuntu 22.04 LTS must accept personal identity verification (PIV) credentials."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260574r958816_rule", "$stig_result", "dpkg -l | grep opensc-pkcs11", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260575r1015020_rule: Ubuntu 22.04 LTS must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260575r1015020_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that the "pam_pkcs11.so" module is configured by using the following command: 
 
     $ grep -i pam_pkcs11.so /etc/pam.d/common-auth 
     auth     [success=2 default=ignore]     pam_pkcs11.so  
 
If "pam_pkcs11.so" is commented out, or is missing, this is a finding. 
 
Verify the sshd daemon allows public key authentication by using the following command: 
  
     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'pubkeyauthentication' 
     /etc/ssh/sshd_config:PubkeyAuthentication yes 
 
If "PubkeyAuthentication" is not set to "yes", is commented out, is missing, or conflicting results are returned, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i pam_pkcs11.so /etc/pam.d/common-auth"
output_0=$(eval "grep -i pam_pkcs11.so /etc/pam.d/common-auth" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i pam_pkcs11.so /etc/pam.d/common-auth" "SV-260575r1015020_rule")
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
print_rule_result "$rule_result" "SV-260575r1015020_rule" "Ubuntu 22.04 LTS must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260575r1015020_rule", "$stig_result", "grep -i pam_pkcs11.so /etc/pam.d/common-auth", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260576r958818_rule: Ubuntu 22.04 LTS must electronically verify personal identity verification (PIV) credentials.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260576r958818_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must electronically verify personal identity verification (PIV) credentials."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS electronically verifies PIV credentials via certificate status checking by using the following command:  
  
     $ sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ocsp_on 
     cert_policy = ca,signature,ocsp_on;  
  
If every returned "cert_policy" line is not set to "ocsp_on", the line is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ocsp_on"
output_0=$(eval "grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ocsp_on" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ocsp_on" "SV-260576r958818_rule")
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
print_rule_result "$rule_result" "SV-260576r958818_rule" "Ubuntu 22.04 LTS must electronically verify personal identity verification (PIV) credentials."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260576r958818_rule", "$stig_result", "grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ocsp_on", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260577r986294_rule: Ubuntu 22.04 LTS, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260577r986294_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS, for PKI-based authentication, has valid certificates by constructing a certification path to an accepted trust anchor.  
  
Determine which pkcs11 module is being used via the "use_pkcs11_module" in "/etc/pam_pkcs11/pam_pkcs11.conf" and then ensure "ca" is enabled in "cert_policy" by using the following command:  
   
     $ sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ca   
     cert_policy = ca,signature,ocsp_on;  
  
If "cert_policy" is not set to "ca", the line is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ca"
output_0=$(eval "grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ca" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ca" "SV-260577r986294_rule")
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
print_rule_result "$rule_result" "SV-260577r986294_rule" "Ubuntu 22.04 LTS, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260577r986294_rule", "$stig_result", "grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ca", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260578r1015021_rule: Ubuntu 22.04 LTS for PKI-based authentication, must implement a local cache of revocation data in case of the inability to access revocation information via the network.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260578r1015021_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS for PKI-based authentication, must implement a local cache of revocation data in case of the inability to access revocation information via the network."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS, for PKI-based authentication, uses local revocation data when unable to access it from the network by using the following command: 
 
Note: If smart card authentication is not being used on the system, this is not applicable.  
  
     $ grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep  -E -- 'crl_auto|crl_offline' 
     cert_policy = ca,signature,ocsp_on,crl_auto; 
  
If "cert_policy" is not set to include "crl_auto" or "crl_offline", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep  -E -- 'crl_auto|crl_offline'"
output_0=$(eval "grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep  -E -- 'crl_auto|crl_offline'" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep  -E -- 'crl_auto|crl_offline'" "SV-260578r1015021_rule")
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
print_rule_result "$rule_result" "SV-260578r1015021_rule" "Ubuntu 22.04 LTS for PKI-based authentication, must implement a local cache of revocation data in case of the inability to access revocation information via the network."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260578r1015021_rule", "$stig_result", "grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep  -E -- 'crl_auto|crl_offline'", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260579r958452_rule: Ubuntu 22.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260579r958452_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that "use_mappers" is set to "pwent" in "/etc/pam_pkcs11/pam_pkcs11.conf" file by using the following command:  
  
     $ grep -i use_mappers /etc/pam_pkcs11/pam_pkcs11.conf 
     use_mappers = pwent 
  
If "use_mappers" does not contain "pwent", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i use_mappers /etc/pam_pkcs11/pam_pkcs11.conf"
output_0=$(eval "grep -i use_mappers /etc/pam_pkcs11/pam_pkcs11.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i use_mappers /etc/pam_pkcs11/pam_pkcs11.conf" "SV-260579r958452_rule")
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
print_rule_result "$rule_result" "SV-260579r958452_rule" "Ubuntu 22.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260579r958452_rule", "$stig_result", "grep -i use_mappers /etc/pam_pkcs11/pam_pkcs11.conf", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260580r958868_rule: Ubuntu 22.04 LTS must use DOD PKI-established certificate authorities for verification of the establishment of protected sessions.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260580r958868_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must use DOD PKI-established certificate authorities for verification of the establishment of protected sessions."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify the directory containing the root certificates for Ubuntu 22.04 LTS contains certificate files for DOD PKI-established certificate authorities by iterating over all files in the "/etc/ssl/certs" directory and checking if, at least one, has the subject matching "DOD ROOT CA". 
 
     $ ls /etc/ssl/certs | grep -i DOD 
     DOD_PKE_CA_chain.pem 
 
If no DOD root certificate is found, this is a finding. 
 
Verify that all root certificates present on the system have been approved by the AO. 
 
     $ ls /etc/ssl/certs 
 
If a certificate is present that is not approved by the AO, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} ls /etc/ssl/certs | grep -i DOD"
output_0=$(eval "ls /etc/ssl/certs | grep -i DOD" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "ls /etc/ssl/certs | grep -i DOD" "SV-260580r958868_rule")
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
echo -e "${BLUE}Executing:${NC} ls /etc/ssl/certs"
output_1=$(eval "ls /etc/ssl/certs" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "ls /etc/ssl/certs" "SV-260580r958868_rule")
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
print_rule_result "$rule_result" "SV-260580r958868_rule" "Ubuntu 22.04 LTS must use DOD PKI-established certificate authorities for verification of the establishment of protected sessions."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260580r958868_rule", "$stig_result", "ls /etc/ssl/certs", "$output_1"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260581r958828_rule: Ubuntu 22.04 LTS must be configured such that Pluggable Authentication Module (PAM) prohibits the use of cached authentications after one day.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260581r958828_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must be configured such that Pluggable Authentication Module (PAM) prohibits the use of cached authentications after one day."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that PAM prohibits the use of cached authentications after one day by using the following command: 
 
Note: If smart card authentication is not being used on the system, this requirement is not applicable.  
  
     $ sudo grep -i '^\s*offline_credentials_expiration' /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf 
     /etc/sssd/sssd.conf:offline_credentials_expiration = 1 
 
If "offline_credentials_expiration" is not set to "1", is commented out, is missing, or conflicting results are returned, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i '^\s*offline_credentials_expiration' /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf"
output_0=$(eval "grep -i '^\s*offline_credentials_expiration' /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i '^\s*offline_credentials_expiration' /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf" "SV-260581r958828_rule")
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
print_rule_result "$rule_result" "SV-260581r958828_rule" "Ubuntu 22.04 LTS must be configured such that Pluggable Authentication Module (PAM) prohibits the use of cached authentications after one day."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260581r958828_rule", "$stig_result", "grep -i '^\s*offline_credentials_expiration' /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260582r958944_rule: Ubuntu 22.04 LTS must use a file integrity tool to verify correct operation of all security functions.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260582r958944_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must use a file integrity tool to verify correct operation of all security functions."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify that Advanced Intrusion Detection Environment (AIDE) is installed by using the following command: 
 
     $ dpkg -l | grep aide 
     ii     aide     0.17.4-1     amd64     Advanced Intrusion Detection Environment - dynamic binary 
 
If AIDE is not installed, ask the system administrator how file integrity checks are performed on the system.  
 
If there is no application installed to perform integrity checks, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} dpkg -l | grep aide"
output_0=$(eval "dpkg -l | grep aide" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "dpkg -l | grep aide" "SV-260582r958944_rule")
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
print_rule_result "$rule_result" "SV-260582r958944_rule" "Ubuntu 22.04 LTS must use a file integrity tool to verify correct operation of all security functions."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260582r958944_rule", "$stig_result", "dpkg -l | grep aide", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260583r958944_rule: Ubuntu 22.04 LTS must configure AIDE to perform file integrity checking on the file system.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260583r958944_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must configure AIDE to perform file integrity checking on the file system."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that Advanced Intrusion Detection Environment (AIDE) is configured and operating correctly by using the following command (this will take a few minutes): 
 
Note: If AIDE is not installed, this requirement is not applicable. 
 
     $ sudo aide -c /etc/aide/aide.conf --check 
 
Example output: 
 
Start timestamp: 2024-04-01 04:20:00 +1300 (AIDE 0.17.4) 
AIDE found differences between database and filesystem!! 
Ignored e2fs attributes: EIh 
... 
 
If AIDE is being used to perform file integrity checks but the command fails, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} aide -c /etc/aide/aide.conf --check"
output_0=$(eval "aide -c /etc/aide/aide.conf --check" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "aide -c /etc/aide/aide.conf --check" "SV-260583r958944_rule")
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
print_rule_result "$rule_result" "SV-260583r958944_rule" "Ubuntu 22.04 LTS must configure AIDE to perform file integrity checking on the file system."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260583r958944_rule", "$stig_result", "aide -c /etc/aide/aide.conf --check", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260584r958794_rule: Ubuntu 22.04 LTS must notify designated personnel if baseline configurations are changed in an unauthorized manner. The file integrity tool must notify the system administrator when changes to the baseline configuration or anomalies in the operation of any security functions are discovered.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260584r958794_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must notify designated personnel if baseline configurations are changed in an unauthorized manner. The file integrity tool must notify the system administrator when changes to the baseline configuration or anomalies in the operation of any security functions are discovered."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that Advanced Intrusion Detection Environment (AIDE) notifies the system administrator when anomalies in the operation of any security functions are discovered by using the following command:  
  
     $ grep -i '^\s*silentreports' /etc/default/aide  
     SILENTREPORTS=no 
  
If "SILENTREPORTS" is set to "yes", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i '^\s*silentreports' /etc/default/aide"
output_0=$(eval "grep -i '^\s*silentreports' /etc/default/aide" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i '^\s*silentreports' /etc/default/aide" "SV-260584r958794_rule")
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
print_rule_result "$rule_result" "SV-260584r958794_rule" "Ubuntu 22.04 LTS must notify designated personnel if baseline configurations are changed in an unauthorized manner. The file integrity tool must notify the system administrator when changes to the baseline configuration or anomalies in the operation of any security functions are discovered."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260584r958794_rule", "$stig_result", "grep -i '^\s*silentreports' /etc/default/aide", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260585r958946_rule: Ubuntu 22.04 LTS must be configured so that the script that runs each 30 days or less to check file integrity is the default.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260585r958946_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must be configured so that the script that runs each 30 days or less to check file integrity is the default."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that the Advanced Intrusion Detection Environment (AIDE) default script used to check file integrity each 30 days or less is unchanged.  
  
Download the original aide-common package in the /tmp directory:  
  
     $ cd /tmp; apt download aide-common 
  
Fetch the SHA1 of the original script file: 
  
     $ dpkg-deb --fsys-tarfile /tmp/aide-common_*.deb | tar -xO ./usr/share/aide/config/cron.daily/aide | sha1sum 
     b71bb2cafaedf15ec3ac2f566f209d3260a37af0  -  
  
Compare with the SHA1 of the file in the daily or monthly cron directory:  
  
     $ sha1sum /etc/cron.{daily,monthly}/aide 2>/dev/null 
     b71bb2cafaedf15ec3ac2f566f209d3260a37af0  /etc/cron.daily/aide 
  
If there is no AIDE script file in the cron directories, or the SHA1 value of at least one file in the daily or monthly cron directory does not match the SHA1 of the original, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} cd /tmp; apt download aide-common"
output_0=$(eval "cd /tmp; apt download aide-common" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "cd /tmp; apt download aide-common" "SV-260585r958946_rule")
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
echo -e "${BLUE}Executing:${NC} dpkg-deb --fsys-tarfile /tmp/aide-common_*.deb | tar -xO ./usr/share/aide/config/cron.daily/aide | sha1sum"
output_1=$(eval "dpkg-deb --fsys-tarfile /tmp/aide-common_*.deb | tar -xO ./usr/share/aide/config/cron.daily/aide | sha1sum" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "dpkg-deb --fsys-tarfile /tmp/aide-common_*.deb | tar -xO ./usr/share/aide/config/cron.daily/aide | sha1sum" "SV-260585r958946_rule")
echo -e "${BLUE}Command 2 Result:${NC} $cmd_result_1"

# If any command fails, the whole rule fails
if [ "$cmd_result_1" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_1" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_1" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Command 3
echo -e "${BLUE}Executing:${NC} sha1sum /etc/cron.{daily,monthly}/aide 2>/dev/null"
output_2=$(eval "sha1sum /etc/cron.{daily,monthly}/aide 2>/dev/null" 2>&1)
exit_code_2=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_2"
echo -e "${BLUE}Output:${NC}"
echo "$output_2"
echo ""

# Evaluate command result using function
cmd_result_2=$(evaluate_command_result "$exit_code_2" "$output_2" "positive" "sha1sum /etc/cron.{daily,monthly}/aide 2>/dev/null" "SV-260585r958946_rule")
echo -e "${BLUE}Command 3 Result:${NC} $cmd_result_2"

# If any command fails, the whole rule fails
if [ "$cmd_result_2" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_2" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_2" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-260585r958946_rule" "Ubuntu 22.04 LTS must be configured so that the script that runs each 30 days or less to check file integrity is the default."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260585r958946_rule", "$stig_result", "sha1sum /etc/cron.{daily,monthly}/aide 2>/dev/null", "$output_2"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260586r991567_rule: Ubuntu 22.04 LTS must use cryptographic mechanisms to protect the integrity of audit tools.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260586r991567_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must use cryptographic mechanisms to protect the integrity of audit tools."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that Advanced Intrusion Detection Environment (AIDE) is properly configured to use cryptographic mechanisms to protect the integrity of audit tools by using the following command:  
  
     $ grep -E '(\/sbin\/(audit|au))' /etc/aide/aide.conf 
     /sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512  
     /sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512  
     /sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512  
     /sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512  
     /sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512  
     /sbin/audispd p+i+n+u+g+s+b+acl+xattrs+sha512  
     /sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512  
  
If any of the seven lines do not appear as shown, are commented out, or are missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -E '(\/sbin\/(audit|au))' /etc/aide/aide.conf"
output_0=$(eval "grep -E '(\/sbin\/(audit|au))' /etc/aide/aide.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -E '(\/sbin\/(audit|au))' /etc/aide/aide.conf" "SV-260586r991567_rule")
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
print_rule_result "$rule_result" "SV-260586r991567_rule" "Ubuntu 22.04 LTS must use cryptographic mechanisms to protect the integrity of audit tools."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260586r991567_rule", "$stig_result", "grep -E '(\/sbin\/(audit|au))' /etc/aide/aide.conf", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260587r959008_rule: Ubuntu 22.04 LTS must have a crontab script running weekly to offload audit events of standalone systems.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260587r959008_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must have a crontab script running weekly to offload audit events of standalone systems."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify there is a script that offloads audit data and that script runs weekly by using the following command: 
 
Note: If the system is not connected to a network, this requirement is not applicable. 
  
     $ ls /etc/cron.weekly 
      
  
Check if the script inside the file does offloading of audit logs to external media.  
  
If the script file does not exist or does not offload audit logs, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} ls /etc/cron.weekly"
output_0=$(eval "ls /etc/cron.weekly" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "ls /etc/cron.weekly" "SV-260587r959008_rule")
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
print_rule_result "$rule_result" "SV-260587r959008_rule" "Ubuntu 22.04 LTS must have a crontab script running weekly to offload audit events of standalone systems."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260587r959008_rule", "$stig_result", "ls /etc/cron.weekly", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260588r991562_rule: Ubuntu 22.04 LTS must be configured to preserve log records from failure events.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260588r991562_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must be configured to preserve log records from failure events."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify the log service is installed properly by using the following command:  
  
     $ dpkg -l | grep rsyslog 
     ii     rsyslog     8.2112.0-2ubuntu2.2     amd64     reliable system and kernel logging daemon 
  
If the "rsyslog" package is not installed, this is a finding.  
  
Check that the log service is enabled and active by using the following commands:  
 
     $ systemctl is-enabled rsyslog.service 
     enabled  
  
     $ systemctl is-active rsyslog.service 
     active  
  
If "rsyslog.service" is not enabled and active, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} dpkg -l | grep rsyslog"
output_0=$(eval "dpkg -l | grep rsyslog" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "dpkg -l | grep rsyslog" "SV-260588r991562_rule")
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
echo -e "${BLUE}Executing:${NC} systemctl is-enabled rsyslog.service"
output_1=$(eval "systemctl is-enabled rsyslog.service" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "systemctl is-enabled rsyslog.service" "SV-260588r991562_rule")
echo -e "${BLUE}Command 2 Result:${NC} $cmd_result_1"

# If any command fails, the whole rule fails
if [ "$cmd_result_1" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_1" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_1" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Command 3
echo -e "${BLUE}Executing:${NC} systemctl is-active rsyslog.service"
output_2=$(eval "systemctl is-active rsyslog.service" 2>&1)
exit_code_2=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_2"
echo -e "${BLUE}Output:${NC}"
echo "$output_2"
echo ""

# Evaluate command result using function
cmd_result_2=$(evaluate_command_result "$exit_code_2" "$output_2" "positive" "systemctl is-active rsyslog.service" "SV-260588r991562_rule")
echo -e "${BLUE}Command 3 Result:${NC} $cmd_result_2"

# If any command fails, the whole rule fails
if [ "$cmd_result_2" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_2" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_2" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-260588r991562_rule" "Ubuntu 22.04 LTS must be configured to preserve log records from failure events."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260588r991562_rule", "$stig_result", "systemctl is-active rsyslog.service", "$output_2"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260589r958406_rule: Ubuntu 22.04 LTS must monitor remote access methods.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260589r958406_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must monitor remote access methods."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that Ubuntu 22.04 LTS monitors all remote access methods by using the following command:  
  
     $  grep -Er '^(auth\.\*,authpriv\.\*|daemon\.\*)' /etc/rsyslog.* 
     /etc/rsyslog.d/50-default.conf:auth.*,authpriv.* /var/log/secure 
     /etc/rsyslog.d/50-default.conf:daemon.* /var/log/messages 
  
If "auth.*", "authpriv.*", or "daemon.*" are not configured to be logged in at least one of the config files, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -Er '^(auth\.\*,authpriv\.\*|daemon\.\*)' /etc/rsyslog.*"
output_0=$(eval "grep -Er '^(auth\.\*,authpriv\.\*|daemon\.\*)' /etc/rsyslog.*" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -Er '^(auth\.\*,authpriv\.\*|daemon\.\*)' /etc/rsyslog.*" "SV-260589r958406_rule")
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
print_rule_result "$rule_result" "SV-260589r958406_rule" "Ubuntu 22.04 LTS must monitor remote access methods."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260589r958406_rule", "$stig_result", "grep -Er '^(auth\.\*,authpriv\.\*|daemon\.\*)' /etc/rsyslog.*", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260590r1015022_rule: Ubuntu 22.04 LTS must have the "auditd" package installed.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260590r1015022_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must have the "auditd" package installed."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify the "auditd" package is installed by using the following command:  
  
     $ dpkg -l | grep auditd 
     ii     libauditd     1:3.0.7-1build1     amd64     User space tools for security auditing 
 
If the "auditd" package is not installed, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} dpkg -l | grep auditd"
output_0=$(eval "dpkg -l | grep auditd" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "dpkg -l | grep auditd" "SV-260590r1015022_rule")
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
print_rule_result "$rule_result" "SV-260590r1015022_rule" "Ubuntu 22.04 LTS must have the "auditd" package installed."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260590r1015022_rule", "$stig_result", "dpkg -l | grep auditd", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260591r1015023_rule: Ubuntu 22.04 LTS must produce audit records and reports containing information to establish when, where, what type, the source, and the outcome for all DOD-defined auditable events and actions in near real time.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260591r1015023_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must produce audit records and reports containing information to establish when, where, what type, the source, and the outcome for all DOD-defined auditable events and actions in near real time."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} service\n"

# Check Content:
cat << 'EOF'
Verify the "auditd.service" is enabled and active by using the following commands:  
  
     $ systemctl is-enabled auditd.service 
     enabled 
  
     $ systemctl is-active auditd.service 
     active  
  
If the "auditd.service" is not enabled and active, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} systemctl is-enabled auditd.service"
output_0=$(eval "systemctl is-enabled auditd.service" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "systemctl is-enabled auditd.service" "SV-260591r1015023_rule")
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
echo -e "${BLUE}Executing:${NC} systemctl is-active auditd.service"
output_1=$(eval "systemctl is-active auditd.service" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "systemctl is-active auditd.service" "SV-260591r1015023_rule")
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
print_rule_result "$rule_result" "SV-260591r1015023_rule" "Ubuntu 22.04 LTS must produce audit records and reports containing information to establish when, where, what type, the source, and the outcome for all DOD-defined auditable events and actions in near real time."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260591r1015023_rule", "$stig_result", "systemctl is-active auditd.service", "$output_1"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260592r958754_rule: Ubuntu 22.04 LTS audit event multiplexor must be configured to offload audit logs onto a different system from the system being audited.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260592r958754_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS audit event multiplexor must be configured to offload audit logs onto a different system from the system being audited."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} package\n"

# Check Content:
cat << 'EOF'
Verify the audit event multiplexor is configured to offload audit records to a different system from the system being audited.  
  
Check if the "audispd-plugins" package is installed:  
  
     $ dpkg -l | grep audispd-plugins 
     ii     audispd-plugins     1:3.0.7-1build1     amd64     Plugins for the audit event dispatcher 
  
If the "audispd-plugins" package is not installed, this is a finding.  
  
Check that the records are being offloaded to a remote server by using the following command:  
  
     $ sudo grep -i active /etc/audit/plugins.d/au-remote.conf 
     active = yes  
  
If "active" is not set to "yes", or the line is commented out, or is missing, this is a finding.  
  
Check that audisp-remote plugin is configured to send audit logs to a different system:  
  
     $ sudo grep -i remote_server /etc/audit/audisp-remote.conf 
     remote_server = 240.9.19.81 
  
If the "remote_server" parameter is not set, is set with a local IP address, or is set with an invalid IP address, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} dpkg -l | grep audispd-plugins"
output_0=$(eval "dpkg -l | grep audispd-plugins" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "dpkg -l | grep audispd-plugins" "SV-260592r958754_rule")
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
echo -e "${BLUE}Executing:${NC} grep -i active /etc/audit/plugins.d/au-remote.conf"
output_1=$(eval "grep -i active /etc/audit/plugins.d/au-remote.conf" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "grep -i active /etc/audit/plugins.d/au-remote.conf" "SV-260592r958754_rule")
echo -e "${BLUE}Command 2 Result:${NC} $cmd_result_1"

# If any command fails, the whole rule fails
if [ "$cmd_result_1" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_1" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_1" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Command 3
echo -e "${BLUE}Executing:${NC} grep -i remote_server /etc/audit/audisp-remote.conf"
output_2=$(eval "grep -i remote_server /etc/audit/audisp-remote.conf" 2>&1)
exit_code_2=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_2"
echo -e "${BLUE}Output:${NC}"
echo "$output_2"
echo ""

# Evaluate command result using function
cmd_result_2=$(evaluate_command_result "$exit_code_2" "$output_2" "positive" "grep -i remote_server /etc/audit/audisp-remote.conf" "SV-260592r958754_rule")
echo -e "${BLUE}Command 3 Result:${NC} $cmd_result_2"

# If any command fails, the whole rule fails
if [ "$cmd_result_2" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_2" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_2" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-260592r958754_rule" "Ubuntu 22.04 LTS audit event multiplexor must be configured to offload audit logs onto a different system from the system being audited."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260592r958754_rule", "$stig_result", "grep -i remote_server /etc/audit/audisp-remote.conf", "$output_2"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260593r958424_rule: Ubuntu 22.04 LTS must alert the information system security officer (ISSO) and system administrator (SA) in the event of an audit processing failure.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260593r958424_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must alert the information system security officer (ISSO) and system administrator (SA) in the event of an audit processing failure."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that the SA and ISSO are notified in the event of an audit processing failure by using the following command: 
 
Note: An email package must be installed on the system for email notifications to be sent. 
  
     $ sudo grep -i action_mail_acct /etc/audit/auditd.conf 
     action_mail_acct =  
  
If "action_mail_acct" is not set to the email address of the SA and/or ISSO, is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i action_mail_acct /etc/audit/auditd.conf"
output_0=$(eval "grep -i action_mail_acct /etc/audit/auditd.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i action_mail_acct /etc/audit/auditd.conf" "SV-260593r958424_rule")
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
print_rule_result "$rule_result" "SV-260593r958424_rule" "Ubuntu 22.04 LTS must alert the information system security officer (ISSO) and system administrator (SA) in the event of an audit processing failure."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260593r958424_rule", "$stig_result", "grep -i action_mail_acct /etc/audit/auditd.conf", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260594r958426_rule: Ubuntu 22.04 LTS must shut down by default upon audit failure.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260594r958426_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must shut down by default upon audit failure."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS takes the appropriate action when the audit storage volume is full by using the following command:  
  
     $ sudo grep -i disk_full_action /etc/audit/auditd.conf 
     disk_full_action = HALT 
  
If "disk_full_action" is not set to "HALT", "SYSLOG", or "SINGLE", is commented out, or is missing, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i disk_full_action /etc/audit/auditd.conf"
output_0=$(eval "grep -i disk_full_action /etc/audit/auditd.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i disk_full_action /etc/audit/auditd.conf" "SV-260594r958426_rule")
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
print_rule_result "$rule_result" "SV-260594r958426_rule" "Ubuntu 22.04 LTS must shut down by default upon audit failure."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260594r958426_rule", "$stig_result", "grep -i disk_full_action /etc/audit/auditd.conf", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260595r958752_rule: Ubuntu 22.04 LTS must allocate audit record storage capacity to store at least one weeks' worth of audit records, when audit records are not immediately sent to a central audit record storage facility.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260595r958752_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must allocate audit record storage capacity to store at least one weeks' worth of audit records, when audit records are not immediately sent to a central audit record storage facility."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS allocates audit record storage capacity to store at least one week's worth of audit records when audit records are not immediately sent to a central audit record storage facility.  
  
Determine which partition the audit records are being written to by using the following command:  
  
     $ sudo grep -i log_file /etc/audit/auditd.conf 
     log_file = /var/log/audit/audit.log 
  
Check the size of the partition that audit records are written to (with the example being "/var/log/audit/") by using the following command:  
  
     $ sudo df -h /var/log/audit/ 
     /dev/sda2 24G 10.4G 13.6G 43% /var/log/audit 
  
If the audit records are not written to a partition made specifically for audit records ("/var/log/audit" as a separate partition), determine the amount of space being used by other files in the partition by using the following command:  
  
     $ sudo du -sh  
     1.8G /var/log/audit  
  
Note: The partition size needed to capture a week's worth of audit records is based on the activity level of the system and the total storage capacity available.  
  
If the audit record partition is not allocated for sufficient storage capacity, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i log_file /etc/audit/auditd.conf"
output_0=$(eval "grep -i log_file /etc/audit/auditd.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i log_file /etc/audit/auditd.conf" "SV-260595r958752_rule")
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
echo -e "${BLUE}Executing:${NC} df -h /var/log/audit/"
output_1=$(eval "df -h /var/log/audit/" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "df -h /var/log/audit/" "SV-260595r958752_rule")
echo -e "${BLUE}Command 2 Result:${NC} $cmd_result_1"

# If any command fails, the whole rule fails
if [ "$cmd_result_1" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_1" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_1" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Command 3
echo -e "${BLUE}Executing:${NC} du -sh"
output_2=$(eval "du -sh" 2>&1)
exit_code_2=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_2"
echo -e "${BLUE}Output:${NC}"
echo "$output_2"
echo ""

# Evaluate command result using function
cmd_result_2=$(evaluate_command_result "$exit_code_2" "$output_2" "positive" "du -sh" "SV-260595r958752_rule")
echo -e "${BLUE}Command 3 Result:${NC} $cmd_result_2"

# If any command fails, the whole rule fails
if [ "$cmd_result_2" == "FAIL" ]; then
    rule_result="FAIL"
elif [ "$cmd_result_2" == "MANUAL" ] && [ "$rule_result" != "FAIL" ]; then
    rule_result="MANUAL"
elif [ "$cmd_result_2" == "NOT_CHECKED" ] && [ "$rule_result" != "FAIL" ] && [ "$rule_result" != "MANUAL" ]; then
    rule_result="NOT_CHECKED"
fi


# Check if this is actually a manual check based on content
if [ $(is_manual_check "$check_content") == "true" ]; then
    echo -e "${YELLOW}This appears to be a manual check based on content.${NC}"
    rule_result="MANUAL"
fi

# Print the final result for this rule
print_rule_result "$rule_result" "SV-260595r958752_rule" "Ubuntu 22.04 LTS must allocate audit record storage capacity to store at least one weeks' worth of audit records, when audit records are not immediately sent to a central audit record storage facility."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260595r958752_rule", "$stig_result", "du -sh", "$output_2"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260596r971542_rule: Ubuntu 22.04 LTS must immediately notify the system administrator (SA) and information system security officer (ISSO) when the audit record storage volume reaches 25 percent remaining of the allocated capacity.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260596r971542_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must immediately notify the system administrator (SA) and information system security officer (ISSO) when the audit record storage volume reaches 25 percent remaining of the allocated capacity."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS is configured to notify the SA and ISSO when the audit record storage volume reaches 25 percent remaining of the allocated capacity by using the following command:  
 
     $ sudo grep -i space_left /etc/audit/auditd.conf 
     space_left = 25% 
     space_left_action = email 
  
If "space_left" is set to a value less than "25%", is commented out, or is missing, this is a finding.

If "space_left_action" is not set to "email", is commented out, or is missing, this is a finding. 
  
Note: If the "space_left_action" is set to "exec", the system executes a designated script. If this script informs the SA of the event, this is not a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i space_left /etc/audit/auditd.conf"
output_0=$(eval "grep -i space_left /etc/audit/auditd.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i space_left /etc/audit/auditd.conf" "SV-260596r971542_rule")
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
print_rule_result "$rule_result" "SV-260596r971542_rule" "Ubuntu 22.04 LTS must immediately notify the system administrator (SA) and information system security officer (ISSO) when the audit record storage volume reaches 25 percent remaining of the allocated capacity."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260596r971542_rule", "$stig_result", "grep -i space_left /etc/audit/auditd.conf", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260597r958434_rule: Ubuntu 22.04 LTS must be configured so that audit log files are not read- or write-accessible by unauthorized users.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260597r958434_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must be configured so that audit log files are not read- or write-accessible by unauthorized users."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that the audit log files have a mode of "600" or less permissive.  
  
Determine where the audit logs are stored by using the following command:  
  
     $ sudo grep -iw log_file /etc/audit/auditd.conf 
     log_file = /var/log/audit/audit.log 
  
Using the path of the directory containing the audit logs, determine if the audit log files have a mode of "600" or less by using the following command:  
  
     $ sudo stat -c "%n %a" /var/log/audit/* 
     /var/log/audit/audit.log 600 
  
If the audit log files have a mode more permissive than "600", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -iw log_file /etc/audit/auditd.conf"
output_0=$(eval "grep -iw log_file /etc/audit/auditd.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -iw log_file /etc/audit/auditd.conf" "SV-260597r958434_rule")
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
echo -e "${BLUE}Executing:${NC} stat -c \"%n %a\" /var/log/audit/*"
output_1=$(eval "stat -c \"%n %a\" /var/log/audit/*" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "stat -c \"%n %a\" /var/log/audit/*" "SV-260597r958434_rule")
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
print_rule_result "$rule_result" "SV-260597r958434_rule" "Ubuntu 22.04 LTS must be configured so that audit log files are not read- or write-accessible by unauthorized users."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260597r958434_rule", "$stig_result", "stat -c \"%n %a\" /var/log/audit/*", "$output_1"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260598r958434_rule: Ubuntu 22.04 LTS must be configured to permit only authorized users ownership of the audit log files.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260598r958434_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must be configured to permit only authorized users ownership of the audit log files."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify the audit log files are owned by "root" account.  
  
Determine where the audit logs are stored by using the following command:  
  
     $ sudo grep -iw log_file /etc/audit/auditd.conf 
     log_file = /var/log/audit/audit.log  
  
Using the path of the directory containing the audit logs, determine if the audit log files are owned by the "root" user by using the following command:  
  
     $ sudo stat -c "%n %U" /var/log/audit/* 
     /var/log/audit/audit.log root  
  
If the audit log files are owned by a user other than "root", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -iw log_file /etc/audit/auditd.conf"
output_0=$(eval "grep -iw log_file /etc/audit/auditd.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -iw log_file /etc/audit/auditd.conf" "SV-260598r958434_rule")
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
echo -e "${BLUE}Executing:${NC} stat -c \"%n %U\" /var/log/audit/*"
output_1=$(eval "stat -c \"%n %U\" /var/log/audit/*" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "stat -c \"%n %U\" /var/log/audit/*" "SV-260598r958434_rule")
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
print_rule_result "$rule_result" "SV-260598r958434_rule" "Ubuntu 22.04 LTS must be configured to permit only authorized users ownership of the audit log files."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260598r958434_rule", "$stig_result", "stat -c \"%n %U\" /var/log/audit/*", "$output_1"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260599r958434_rule: Ubuntu 22.04 LTS must permit only authorized groups ownership of the audit log files.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260599r958434_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must permit only authorized groups ownership of the audit log files."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify the group owner of newly created audit logs is "root" by using the following command:  
 
     $ sudo grep -iw log_group /etc/audit/auditd.conf 
     log_group = root 
 
If "log_group" is not set to "root", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -iw log_group /etc/audit/auditd.conf"
output_0=$(eval "grep -iw log_group /etc/audit/auditd.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -iw log_group /etc/audit/auditd.conf" "SV-260599r958434_rule")
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
print_rule_result "$rule_result" "SV-260599r958434_rule" "Ubuntu 22.04 LTS must permit only authorized groups ownership of the audit log files."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260599r958434_rule", "$stig_result", "grep -iw log_group /etc/audit/auditd.conf", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260600r958438_rule: Ubuntu 22.04 LTS must be configured so that the audit log directory is not write-accessible by unauthorized users.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260600r958438_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must be configured so that the audit log directory is not write-accessible by unauthorized users."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify that the audit log directory has a mode of "750" or less permissive.  
  
Determine where the audit logs are stored by using the following command:  
 
     $ sudo grep -iw log_file /etc/audit/auditd.conf 
     log_file = /var/log/audit/audit.log 
  
Using the path of the directory containing the audit logs, determine if the directory has a mode of "750" or less by using the following command:  
  
     $ sudo stat -c "%n %a" /var/log/audit 
     /var/log/audit 750 
  
If the audit log directory has a mode more permissive than "750", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -iw log_file /etc/audit/auditd.conf"
output_0=$(eval "grep -iw log_file /etc/audit/auditd.conf" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -iw log_file /etc/audit/auditd.conf" "SV-260600r958438_rule")
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
echo -e "${BLUE}Executing:${NC} stat -c \"%n %a\" /var/log/audit"
output_1=$(eval "stat -c \"%n %a\" /var/log/audit" 2>&1)
exit_code_1=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_1"
echo -e "${BLUE}Output:${NC}"
echo "$output_1"
echo ""

# Evaluate command result using function
cmd_result_1=$(evaluate_command_result "$exit_code_1" "$output_1" "positive" "stat -c \"%n %a\" /var/log/audit" "SV-260600r958438_rule")
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
print_rule_result "$rule_result" "SV-260600r958438_rule" "Ubuntu 22.04 LTS must be configured so that the audit log directory is not write-accessible by unauthorized users."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260600r958438_rule", "$stig_result", "stat -c \"%n %a\" /var/log/audit", "$output_1"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260601r958444_rule: Ubuntu 22.04 LTS must be configured so that audit configuration files are not write-accessible by unauthorized users.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260601r958444_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must be configured so that audit configuration files are not write-accessible by unauthorized users."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify that "/etc/audit/audit.rules", "/etc/audit/auditd.conf", and "/etc/audit/rules.d/*" files have a mode of "640" or less permissive by using the following command:  
  
     $ sudo ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print $1, $9}' 
     -rw-r----- /etc/audit/audit.rules 
     -rw-r----- /etc/audit/auditd.conf 
     -rw-r----- /etc/audit/rules.d/audit.rules 
 
If "/etc/audit/audit.rules", "/etc/audit/auditd.conf", or "/etc/audit/rules.d/*" files have a mode more permissive than "640", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print \$1, \$9}'"
output_0=$(eval "ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print \$1, \$9}'" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print \$1, \$9}'" "SV-260601r958444_rule")
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
print_rule_result "$rule_result" "SV-260601r958444_rule" "Ubuntu 22.04 LTS must be configured so that audit configuration files are not write-accessible by unauthorized users."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260601r958444_rule", "$stig_result", "ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print \$1, \$9}'", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260602r958444_rule: Ubuntu 22.04 LTS must permit only authorized accounts to own the audit configuration files.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260602r958444_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must permit only authorized accounts to own the audit configuration files."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify that "/etc/audit/audit.rules", "/etc/audit/auditd.conf", and "/etc/audit/rules.d/*" files are owned by root account by using the following command:  
  
     $ sudo ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print $3, $9}' 
     root /etc/audit/audit.rules 
     root /etc/audit/auditd.conf 
     root /etc/audit/rules.d/audit.rules 
 
If "/etc/audit/audit.rules", "/etc/audit/auditd.conf", or "/etc/audit/rules.d/*" files are owned by a user other than "root", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print \$3, \$9}'"
output_0=$(eval "ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print \$3, \$9}'" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print \$3, \$9}'" "SV-260602r958444_rule")
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
print_rule_result "$rule_result" "SV-260602r958444_rule" "Ubuntu 22.04 LTS must permit only authorized accounts to own the audit configuration files."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260602r958444_rule", "$stig_result", "ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print \$3, \$9}'", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260603r958444_rule: Ubuntu 22.04 LTS must permit only authorized groups to own the audit configuration files.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260603r958444_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must permit only authorized groups to own the audit configuration files."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify that "/etc/audit/audit.rules", "/etc/audit/auditd.conf", and "/etc/audit/rules.d/*" files are owned by root group by using the following command:  
  
     $ sudo ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print $4, $9}'  
     root /etc/audit/audit.rules 
     root /etc/audit/auditd.conf 
     root /etc/audit/rules.d/audit.rules 
  
If "/etc/audit/audit.rules", "/etc/audit/auditd.conf", or "/etc/audit/rules.d/*" files are owned by a group other than "root", this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print \$4, \$9}'"
output_0=$(eval "ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print \$4, \$9}'" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print \$4, \$9}'" "SV-260603r958444_rule")
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
print_rule_result "$rule_result" "SV-260603r958444_rule" "Ubuntu 22.04 LTS must permit only authorized groups to own the audit configuration files."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260603r958444_rule", "$stig_result", "ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print \$4, \$9}'", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260604r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the apparmor_parser command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260604r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the apparmor_parser command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates an audit record upon successful/unsuccessful attempts to use the "apparmor_parser" command by using the following command:  
  
     $ sudo auditctl -l | grep apparmor_parser 
     -a always,exit -S all -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng  
 
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep apparmor_parser"
output_0=$(eval "auditctl -l | grep apparmor_parser" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep apparmor_parser" "SV-260604r958446_rule")
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
print_rule_result "$rule_result" "SV-260604r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the apparmor_parser command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260604r958446_rule", "$stig_result", "auditctl -l | grep apparmor_parser", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260605r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chacl command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260605r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chacl command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates an audit record upon successful/unsuccessful attempts to use the "chacl" command by using the following command:   
 
     $ sudo auditctl -l | grep chacl 
     -a always,exit -S all -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng 
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep chacl"
output_0=$(eval "auditctl -l | grep chacl" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep chacl" "SV-260605r958446_rule")
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
print_rule_result "$rule_result" "SV-260605r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chacl command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260605r958446_rule", "$stig_result", "auditctl -l | grep chacl", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260606r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chage command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260606r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chage command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify that an audit event is generated for any successful/unsuccessful use of the "chage" command by using the following command:  
  
     $ sudo auditctl -l | grep -w chage 
     -a always,exit -S all -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-chage 
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep -w chage"
output_0=$(eval "auditctl -l | grep -w chage" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep -w chage" "SV-260606r958446_rule")
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
print_rule_result "$rule_result" "SV-260606r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chage command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260606r958446_rule", "$stig_result", "auditctl -l | grep -w chage", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260607r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chcon command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260607r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chcon command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates an audit record upon successful/unsuccessful attempts to use the "chcon" command by using the following command:  
  
     $ sudo auditctl -l | grep chcon 
     -a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng 
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep chcon"
output_0=$(eval "auditctl -l | grep chcon" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep chcon" "SV-260607r958446_rule")
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
print_rule_result "$rule_result" "SV-260607r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chcon command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260607r958446_rule", "$stig_result", "auditctl -l | grep chcon", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260608r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chfn command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260608r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chfn command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates audit records upon successful/unsuccessful attempts to use the "chfn" command by using the following command:  
  
     $ sudo auditctl -l | grep /usr/bin/chfn 
     -a always,exit -S all -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-chfn  
  
If the command does not return lines that match the example or the lines are commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep /usr/bin/chfn"
output_0=$(eval "auditctl -l | grep /usr/bin/chfn" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep /usr/bin/chfn" "SV-260608r958446_rule")
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
print_rule_result "$rule_result" "SV-260608r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chfn command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260608r958446_rule", "$stig_result", "auditctl -l | grep /usr/bin/chfn", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260609r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chsh command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260609r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chsh command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates an audit record upon successful/unsuccessful attempts to use the "chsh" command by using the following command:  
  
     $ sudo auditctl -l | grep chsh 
     -a always,exit -S all -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd  
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Notes: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep chsh"
output_0=$(eval "auditctl -l | grep chsh" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep chsh" "SV-260609r958446_rule")
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
print_rule_result "$rule_result" "SV-260609r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chsh command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260609r958446_rule", "$stig_result", "auditctl -l | grep chsh", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260610r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the crontab command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260610r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the crontab command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify that an audit event is generated for any successful/unsuccessful use of the "crontab" command by using the following command:  
  
     $ sudo auditctl -l | grep -w crontab 
     -a always,exit -S all -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-crontab  
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep -w crontab"
output_0=$(eval "auditctl -l | grep -w crontab" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep -w crontab" "SV-260610r958446_rule")
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
print_rule_result "$rule_result" "SV-260610r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the crontab command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260610r958446_rule", "$stig_result", "auditctl -l | grep -w crontab", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260611r991586_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use the fdisk command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260611r991586_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use the fdisk command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS is configured to audit the execution of the partition management program "fdisk" by using the following command:  
  
     $ sudo auditctl -l | grep fdisk 
     -w /usr/sbin/fdisk -p x -k fdisk 
  
If the command does not return a line, or the line is commented out, this is a finding.  
  
Note: The "-k" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep fdisk"
output_0=$(eval "auditctl -l | grep fdisk" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep fdisk" "SV-260611r991586_rule")
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
print_rule_result "$rule_result" "SV-260611r991586_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use the fdisk command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260611r991586_rule", "$stig_result", "auditctl -l | grep fdisk", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260612r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the gpasswd command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260612r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the gpasswd command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify that an audit event is generated for any successful/unsuccessful use of the "gpasswd" command by using the following command: 
  
     $ sudo auditctl -l | grep -w gpasswd 
     -a always,exit -S all -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-gpasswd  
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep -w gpasswd"
output_0=$(eval "auditctl -l | grep -w gpasswd" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep -w gpasswd" "SV-260612r958446_rule")
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
print_rule_result "$rule_result" "SV-260612r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the gpasswd command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260612r958446_rule", "$stig_result", "auditctl -l | grep -w gpasswd", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260613r991586_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use the kmod command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260613r991586_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use the kmod command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS is configured to audit the execution of the module management program "kmod" by using the following command:  
  
     $ sudo auditctl -l | grep kmod  
     -w /bin/kmod -p x -k module  
  
If the command does not return a line, or the line is commented out, this is a finding.  
  
Note: The "-k" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep kmod"
output_0=$(eval "auditctl -l | grep kmod" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep kmod" "SV-260613r991586_rule")
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
print_rule_result "$rule_result" "SV-260613r991586_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use the kmod command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260613r991586_rule", "$stig_result", "auditctl -l | grep kmod", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260614r991586_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use modprobe command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260614r991586_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use modprobe command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify if Ubuntu 22.04 LTS is configured to audit the execution of the module management program "modprobe" with the following command:  
  
     $ sudo auditctl -l | grep /sbin/modprobe 
     -w /sbin/modprobe -p x -k modules  
  
If the command does not return a line, or the line is commented out, this is a finding.  
  
Note: The "-k" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep /sbin/modprobe"
output_0=$(eval "auditctl -l | grep /sbin/modprobe" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep /sbin/modprobe" "SV-260614r991586_rule")
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
print_rule_result "$rule_result" "SV-260614r991586_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use modprobe command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260614r991586_rule", "$stig_result", "auditctl -l | grep /sbin/modprobe", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260615r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the mount command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260615r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the mount command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates audit records upon successful/unsuccessful attempts to use the "mount" command by using the following command:  
  
     $ sudo auditctl -l | grep /usr/bin/mount 
     -a always,exit -S all -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount  
  
If the command does not return lines that match the example or the lines are commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep /usr/bin/mount"
output_0=$(eval "auditctl -l | grep /usr/bin/mount" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep /usr/bin/mount" "SV-260615r958446_rule")
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
print_rule_result "$rule_result" "SV-260615r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the mount command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260615r958446_rule", "$stig_result", "auditctl -l | grep /usr/bin/mount", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260616r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the newgrp command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260616r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the newgrp command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates an audit record upon successful/unsuccessful attempts to use the "newgrp" command by using the following command:   
  
     $ sudo auditctl -l | grep newgrp 
     -a always,exit -S all -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd 
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep newgrp"
output_0=$(eval "auditctl -l | grep newgrp" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep newgrp" "SV-260616r958446_rule")
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
print_rule_result "$rule_result" "SV-260616r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the newgrp command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260616r958446_rule", "$stig_result", "auditctl -l | grep newgrp", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260617r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the pam_timestamp_check command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260617r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the pam_timestamp_check command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify that an audit event is generated for any successful/unsuccessful use of the "pam_timestamp_check" command by using the following command:  
   
     $ sudo auditctl -l | grep -w pam_timestamp_check 
     -a always,exit -S all -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-pam_timestamp_check  
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep -w pam_timestamp_check"
output_0=$(eval "auditctl -l | grep -w pam_timestamp_check" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep -w pam_timestamp_check" "SV-260617r958446_rule")
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
print_rule_result "$rule_result" "SV-260617r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the pam_timestamp_check command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260617r958446_rule", "$stig_result", "auditctl -l | grep -w pam_timestamp_check", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260618r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the passwd command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260618r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the passwd command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify that an audit event is generated for any successful/unsuccessful use of the "passwd" command by using the following command:   
  
     $ sudo auditctl -l | grep -w passwd 
     -a always,exit -S all -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-passwd  
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "key" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep -w passwd"
output_0=$(eval "auditctl -l | grep -w passwd" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep -w passwd" "SV-260618r958446_rule")
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
print_rule_result "$rule_result" "SV-260618r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the passwd command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260618r958446_rule", "$stig_result", "auditctl -l | grep -w passwd", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260619r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the setfacl command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260619r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the setfacl command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates an audit record upon successful/unsuccessful attempts to use the "setfacl" command by using the following command:  
  
     $ sudo auditctl -l | grep setfacl 
     -a always,exit -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng  
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep setfacl"
output_0=$(eval "auditctl -l | grep setfacl" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep setfacl" "SV-260619r958446_rule")
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
print_rule_result "$rule_result" "SV-260619r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the setfacl command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260619r958446_rule", "$stig_result", "auditctl -l | grep setfacl", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260620r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the ssh-agent command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260620r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the ssh-agent command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates an audit record upon successful/unsuccessful attempts to use the "ssh-agent" command by using the following command:  
  
     $ sudo auditctl -l | grep /usr/bin/ssh-agent 
     -a always,exit -S all -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh  
  
If the command does not return lines that match the example or the lines are commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep /usr/bin/ssh-agent"
output_0=$(eval "auditctl -l | grep /usr/bin/ssh-agent" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep /usr/bin/ssh-agent" "SV-260620r958446_rule")
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
print_rule_result "$rule_result" "SV-260620r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the ssh-agent command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260620r958446_rule", "$stig_result", "auditctl -l | grep /usr/bin/ssh-agent", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260621r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the ssh-keysign command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260621r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the ssh-keysign command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates an audit record upon successful/unsuccessful attempts to use the "ssh-keysign" command by using the following command: 
  
     $ sudo auditctl -l | grep ssh-keysign 
     -a always,exit -S all -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh  
  
If the command does not return lines that match the example or the lines are commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep ssh-keysign"
output_0=$(eval "auditctl -l | grep ssh-keysign" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep ssh-keysign" "SV-260621r958446_rule")
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
print_rule_result "$rule_result" "SV-260621r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the ssh-keysign command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260621r958446_rule", "$stig_result", "auditctl -l | grep ssh-keysign", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260622r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the su command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260622r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the su command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates audit records upon successful/unsuccessful attempts to use the "su" command by using the following command:  
  
     $ sudo auditctl -l | grep /bin/su 
     -a always,exit -S all -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-priv_change  
  
If the command does not return lines that match the example or the lines are commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep /bin/su"
output_0=$(eval "auditctl -l | grep /bin/su" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep /bin/su" "SV-260622r958446_rule")
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
print_rule_result "$rule_result" "SV-260622r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the su command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260622r958446_rule", "$stig_result", "auditctl -l | grep /bin/su", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260623r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the sudo command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260623r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the sudo command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify that an audit event is generated for any successful/unsuccessful use of the "sudo" command by using the following command: 
  
     $ sudo auditctl -l | grep /usr/bin/sudo  
     -a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd  
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep /usr/bin/sudo"
output_0=$(eval "auditctl -l | grep /usr/bin/sudo" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep /usr/bin/sudo" "SV-260623r958446_rule")
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
print_rule_result "$rule_result" "SV-260623r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the sudo command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260623r958446_rule", "$stig_result", "auditctl -l | grep /usr/bin/sudo", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260624r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the sudoedit command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260624r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the sudoedit command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates an audit record upon successful/unsuccessful attempts to use the "sudoedit" command by using the following command:  
  
     $ sudo auditctl -l | grep /usr/bin/sudoedit 
     -a always,exit -S all -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd  
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep /usr/bin/sudoedit"
output_0=$(eval "auditctl -l | grep /usr/bin/sudoedit" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep /usr/bin/sudoedit" "SV-260624r958446_rule")
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
print_rule_result "$rule_result" "SV-260624r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the sudoedit command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260624r958446_rule", "$stig_result", "auditctl -l | grep /usr/bin/sudoedit", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260625r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the umount command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260625r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the umount command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify if Ubuntu 22.04 LTS generates audit records upon successful/unsuccessful attempts to use the "umount" command by using the following command:  
  
     $ sudo auditctl -l | grep /usr/bin/umount 
     -a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-umount  
  
If the command does not return lines that match the example or the lines are commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep /usr/bin/umount"
output_0=$(eval "auditctl -l | grep /usr/bin/umount" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep /usr/bin/umount" "SV-260625r958446_rule")
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
print_rule_result "$rule_result" "SV-260625r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the umount command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260625r958446_rule", "$stig_result", "auditctl -l | grep /usr/bin/umount", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260626r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the unix_update command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260626r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the unix_update command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify that an audit event is generated for any successful/unsuccessful use of the "unix_update" command by using the following command:   
  
     $ sudo auditctl -l | grep -w unix_update 
     -a always,exit -S all -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update  
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep -w unix_update"
output_0=$(eval "auditctl -l | grep -w unix_update" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep -w unix_update" "SV-260626r958446_rule")
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
print_rule_result "$rule_result" "SV-260626r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the unix_update command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260626r958446_rule", "$stig_result", "auditctl -l | grep -w unix_update", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260627r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the usermod command.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260627r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the usermod command."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify that an audit event is generated for any successful/unsuccessful use of the "usermod" command by using the following command:  
  
     $ sudo auditctl -l | grep -w usermod 
     -a always,exit -S all -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-usermod  
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep -w usermod"
output_0=$(eval "auditctl -l | grep -w usermod" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep -w usermod" "SV-260627r958446_rule")
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
print_rule_result "$rule_result" "SV-260627r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the usermod command."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260627r958446_rule", "$stig_result", "auditctl -l | grep -w usermod", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260628r958368_rule: Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260628r958368_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/group" by using the following command: 
 
     $ sudo auditctl -l | grep group 
     -w /etc/group -p wa -k usergroup_modification 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep group"
output_0=$(eval "auditctl -l | grep group" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep group" "SV-260628r958368_rule")
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
print_rule_result "$rule_result" "SV-260628r958368_rule" "Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260628r958368_rule", "$stig_result", "auditctl -l | grep group", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260629r958368_rule: Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260629r958368_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/gshadow" by using the following command: 
 
     $ sudo auditctl -l | grep gshadow 
     -w /etc/gshadow -p wa -k usergroup_modification 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep gshadow"
output_0=$(eval "auditctl -l | grep gshadow" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep gshadow" "SV-260629r958368_rule")
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
print_rule_result "$rule_result" "SV-260629r958368_rule" "Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260629r958368_rule", "$stig_result", "auditctl -l | grep gshadow", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260630r958368_rule: Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260630r958368_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/security/opasswd" by using the following command: 
 
     $ sudo auditctl -l | grep opasswd 
     -w /etc/security/opasswd -p wa -k usergroup_modification 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep opasswd"
output_0=$(eval "auditctl -l | grep opasswd" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep opasswd" "SV-260630r958368_rule")
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
print_rule_result "$rule_result" "SV-260630r958368_rule" "Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260630r958368_rule", "$stig_result", "auditctl -l | grep opasswd", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260631r958368_rule: Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260631r958368_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/passwd" by using the following command: 
 
     $ sudo auditctl -l | grep passwd 
     -w /etc/passwd -p wa -k usergroup_modification 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep passwd"
output_0=$(eval "auditctl -l | grep passwd" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep passwd" "SV-260631r958368_rule")
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
print_rule_result "$rule_result" "SV-260631r958368_rule" "Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260631r958368_rule", "$stig_result", "auditctl -l | grep passwd", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260632r958368_rule: Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260632r958368_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/shadow" by using the following command: 
 
     $ sudo auditctl -l | grep shadow 
     -w /etc/shadow -p wa -k usergroup_modification 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep shadow"
output_0=$(eval "auditctl -l | grep shadow" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep shadow" "SV-260632r958368_rule")
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
print_rule_result "$rule_result" "SV-260632r958368_rule" "Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260632r958368_rule", "$stig_result", "auditctl -l | grep shadow", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260633r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chmod, fchmod, and fchmodat system calls.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260633r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chmod, fchmod, and fchmodat system calls."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates an audit record upon successful/unsuccessful attempts to use the "chmod", "fchmod", and "fchmodat" system calls by using the following command:  
  
     $ sudo auditctl -l | grep chmod 
     -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_chng  
     -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_chng  
  
If the command does not return audit rules for the "chmod", "fchmod" and "fchmodat" syscalls or the lines are commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep chmod"
output_0=$(eval "auditctl -l | grep chmod" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep chmod" "SV-260633r958446_rule")
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
print_rule_result "$rule_result" "SV-260633r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chmod, fchmod, and fchmodat system calls."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260633r958446_rule", "$stig_result", "auditctl -l | grep chmod", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260634r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chown, fchown, fchownat, and lchown system calls.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260634r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chown, fchown, fchownat, and lchown system calls."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates an audit record upon successful/unsuccessful attempts to use the "chown", "fchown", "fchownat", and "lchown" system calls by using the following command: 
  
     $ sudo auditctl -l | grep chown  
     -a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -F key=perm_chng  
     -a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -F key=perm_chng  
  
If the command does not return audit rules for the "chown", "fchown", "fchownat", and "lchown" syscalls or the lines are commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep chown"
output_0=$(eval "auditctl -l | grep chown" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep chown" "SV-260634r958446_rule")
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
print_rule_result "$rule_result" "SV-260634r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chown, fchown, fchownat, and lchown system calls."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260634r958446_rule", "$stig_result", "auditctl -l | grep chown", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260635r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260635r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates an audit record upon unsuccessful attempts to use the "creat", "open", "openat", "open_by_handle_at", "truncate", and "ftruncate" system calls by using the following command:  
  
     $ sudo auditctl -l | grep 'open\|truncate\|creat'  
     -a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access  
     -a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access  
     -a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access  
     -a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access   
  
If the command does not return audit rules for the "creat", "open", "openat", "open_by_handle_at", "truncate", and "ftruncate" syscalls or the lines are commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep 'open\|truncate\|creat'"
output_0=$(eval "auditctl -l | grep 'open\|truncate\|creat'" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep 'open\|truncate\|creat'" "SV-260635r958446_rule")
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
print_rule_result "$rule_result" "SV-260635r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260635r958446_rule", "$stig_result", "auditctl -l | grep 'open\|truncate\|creat'", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260636r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the delete_module system call.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260636r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the delete_module system call."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates an audit record for any successful/unsuccessful attempts to use the "delete_module" syscall by using the following command:  
  
     $ sudo auditctl -l | grep -w delete_module  
     -a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng  
     -a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng  
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep -w delete_module"
output_0=$(eval "auditctl -l | grep -w delete_module" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep -w delete_module" "SV-260636r958446_rule")
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
print_rule_result "$rule_result" "SV-260636r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the delete_module system call."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260636r958446_rule", "$stig_result", "auditctl -l | grep -w delete_module", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260637r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the init_module and finit_module system calls.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260637r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the init_module and finit_module system calls."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates an audit record for any successful/unsuccessful attempts to use the "init_module" and "finit_module" syscalls by using the following command:   
  
     $ sudo auditctl -l | grep init_module  
     -a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng  
     -a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng   
  
If the command does not return audit rules for the "init_module" and "finit_module" syscalls or the lines are commented out, this is a finding. 
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep init_module"
output_0=$(eval "auditctl -l | grep init_module" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep init_module" "SV-260637r958446_rule")
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
print_rule_result "$rule_result" "SV-260637r958446_rule" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the init_module and finit_module system calls."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260637r958446_rule", "$stig_result", "auditctl -l | grep init_module", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260638r958446_rule: Ubuntu 22.04 LTS must generate audit records for any use of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260638r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for any use of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates an audit record upon successful/unsuccessful attempts to use the "setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr", and "lremovexattr" system calls by using the following command:  
  
     $ sudo auditctl -l | grep xattr  
     -a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod  
     -a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod   
     -a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod  
     -a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod   
  
If the command does not return audit rules for the "setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr" and "lremovexattr" syscalls or the lines are commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep xattr"
output_0=$(eval "auditctl -l | grep xattr" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep xattr" "SV-260638r958446_rule")
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
print_rule_result "$rule_result" "SV-260638r958446_rule" "Ubuntu 22.04 LTS must generate audit records for any use of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260638r958446_rule", "$stig_result", "auditctl -l | grep xattr", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260639r991577_rule: Ubuntu 22.04 LTS must generate audit records for any successful/unsuccessful use of unlink, unlinkat, rename, renameat, and rmdir system calls.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260639r991577_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for any successful/unsuccessful use of unlink, unlinkat, rename, renameat, and rmdir system calls."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates audit records for any successful/unsuccessful use of "unlink", "unlinkat", "rename", "renameat", and "rmdir" system calls by using the following command: 
  
     $ sudo auditctl -l | grep 'unlink\|rename\|rmdir'  
     -a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=-1 -F key=delete  
     -a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=-1 -F key=delete  
  
If the command does not return audit rules for the "unlink", "unlinkat", "rename", "renameat", and "rmdir" syscalls or the lines are commented out, this is a finding.  
  
Note: The "key" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep 'unlink\|rename\|rmdir'"
output_0=$(eval "auditctl -l | grep 'unlink\|rename\|rmdir'" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep 'unlink\|rename\|rmdir'" "SV-260639r991577_rule")
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
print_rule_result "$rule_result" "SV-260639r991577_rule" "Ubuntu 22.04 LTS must generate audit records for any successful/unsuccessful use of unlink, unlinkat, rename, renameat, and rmdir system calls."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260639r991577_rule", "$stig_result", "auditctl -l | grep 'unlink\|rename\|rmdir'", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260640r991589_rule: Ubuntu 22.04 LTS must generate audit records for all events that affect the systemd journal files.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260640r991589_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for all events that affect the systemd journal files."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates audit records for all events that affect "/var/log/journal" by using the following command:  
  
     $ sudo auditctl -l | grep journal  
     -w /var/log/journal -p wa -k systemd_journal  
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "-k" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep journal"
output_0=$(eval "auditctl -l | grep journal" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep journal" "SV-260640r991589_rule")
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
print_rule_result "$rule_result" "SV-260640r991589_rule" "Ubuntu 22.04 LTS must generate audit records for all events that affect the systemd journal files."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260640r991589_rule", "$stig_result", "auditctl -l | grep journal", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260641r991581_rule: Ubuntu 22.04 LTS must generate audit records for the /var/log/btmp file.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260641r991581_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for the /var/log/btmp file."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates audit records showing start and stop times for user access to the system via the "/var/log/btmp" file by using the following command:  
  
     $ sudo auditctl -l | grep '/var/log/btmp'  
     -w /var/log/btmp -p wa -k logins  
  
If the command does not return a line matching the example or the line is commented out, this is a finding.  
  
Note: The "-k" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep '/var/log/btmp'"
output_0=$(eval "auditctl -l | grep '/var/log/btmp'" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep '/var/log/btmp'" "SV-260641r991581_rule")
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
print_rule_result "$rule_result" "SV-260641r991581_rule" "Ubuntu 22.04 LTS must generate audit records for the /var/log/btmp file."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260641r991581_rule", "$stig_result", "auditctl -l | grep '/var/log/btmp'", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260642r991581_rule: Ubuntu 22.04 LTS must generate audit records for the /var/log/wtmp file.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260642r991581_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for the /var/log/wtmp file."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates audit records showing start and stop times for user access to the system via the "/var/log/wtmp" file by using the following command:   
  
     $ sudo auditctl -l | grep '/var/log/wtmp'  
     -w /var/log/wtmp -p wa -k logins  
  
If the command does not return a line matching the example or the line is commented out, this is a finding.  
  
Note: The "-k" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep '/var/log/wtmp'"
output_0=$(eval "auditctl -l | grep '/var/log/wtmp'" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep '/var/log/wtmp'" "SV-260642r991581_rule")
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
print_rule_result "$rule_result" "SV-260642r991581_rule" "Ubuntu 22.04 LTS must generate audit records for the /var/log/wtmp file."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260642r991581_rule", "$stig_result", "auditctl -l | grep '/var/log/wtmp'", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260643r991581_rule: Ubuntu 22.04 LTS must generate audit records for the /var/run/utmp file.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260643r991581_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for the /var/run/utmp file."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates audit records showing start and stop times for user access to the system via the "/var/run/utmp" file by using the following command: 
  
     $ sudo auditctl -l | grep '/var/run/utmp'  
     -w /var/run/utmp -p wa -k logins  
  
If the command does not return a line matching the example or the line is commented out, this is a finding.  
  
Note: The "-k" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep '/var/run/utmp'"
output_0=$(eval "auditctl -l | grep '/var/run/utmp'" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep '/var/run/utmp'" "SV-260643r991581_rule")
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
print_rule_result "$rule_result" "SV-260643r991581_rule" "Ubuntu 22.04 LTS must generate audit records for the /var/run/utmp file."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260643r991581_rule", "$stig_result", "auditctl -l | grep '/var/run/utmp'", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260644r958446_rule: Ubuntu 22.04 LTS must generate audit records for the use and modification of faillog file.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260644r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for the use and modification of faillog file."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates an audit record upon successful/unsuccessful modifications to the "faillog" file by using the following command: 
  
     $ sudo auditctl -l | grep faillog  
     -w /var/log/faillog -p wa -k logins  
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "-k" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep faillog"
output_0=$(eval "auditctl -l | grep faillog" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep faillog" "SV-260644r958446_rule")
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
print_rule_result "$rule_result" "SV-260644r958446_rule" "Ubuntu 22.04 LTS must generate audit records for the use and modification of faillog file."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260644r958446_rule", "$stig_result", "auditctl -l | grep faillog", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260645r958446_rule: Ubuntu 22.04 LTS must generate audit records for the use and modification of the lastlog file.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260645r958446_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for the use and modification of the lastlog file."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates an audit record when successful/unsuccessful modifications to the "lastlog" file occur by using the following command:   
  
     $ sudo auditctl -l | grep lastlog  
     -w /var/log/lastlog -p wa -k logins  
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "-k" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep lastlog"
output_0=$(eval "auditctl -l | grep lastlog" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep lastlog" "SV-260645r958446_rule")
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
print_rule_result "$rule_result" "SV-260645r958446_rule" "Ubuntu 22.04 LTS must generate audit records for the use and modification of the lastlog file."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260645r958446_rule", "$stig_result", "auditctl -l | grep lastlog", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260646r991575_rule: Ubuntu 22.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers file occur.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260646r991575_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers file occur."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates audit records for all modifications that affect "/etc/sudoers" by using the following command:  
  
     $ sudo auditctl -l | grep sudoers  
     -w /etc/sudoers -p wa -k privilege_modification  
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "-k" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep sudoers"
output_0=$(eval "auditctl -l | grep sudoers" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep sudoers" "SV-260646r991575_rule")
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
print_rule_result "$rule_result" "SV-260646r991575_rule" "Ubuntu 22.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers file occur."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260646r991575_rule", "$stig_result", "auditctl -l | grep sudoers", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260647r991575_rule: Ubuntu 22.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers.d directory occur.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260647r991575_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers.d directory occur."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS generates audit records for all modifications that affect "/etc/sudoers.d" directory by using the following command:   
  
     $ sudo auditctl -l | grep sudoers.d  
     -w /etc/sudoers.d -p wa -k privilege_modification  
  
If the command does not return a line that matches the example or the line is commented out, this is a finding.  
  
Note: The "-k" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep sudoers.d"
output_0=$(eval "auditctl -l | grep sudoers.d" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep sudoers.d" "SV-260647r991575_rule")
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
print_rule_result "$rule_result" "SV-260647r991575_rule" "Ubuntu 22.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers.d directory occur."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260647r991575_rule", "$stig_result", "auditctl -l | grep sudoers.d", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260648r958730_rule: Ubuntu 22.04 LTS must prevent all software from executing at higher privilege levels than users executing the software and the audit system must be configured to audit the execution of privileged functions.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260648r958730_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must prevent all software from executing at higher privilege levels than users executing the software and the audit system must be configured to audit the execution of privileged functions."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS audits the execution of privilege functions by auditing the "execve" system call by using the following command:  
  
     $ sudo auditctl -l | grep execve 
     -a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv 
     -a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv 
     -a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv 
     -a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv 
  
If the command does not return lines that match the example or the lines are commented out, this is a finding.  
  
Note: The "key=" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep execve"
output_0=$(eval "auditctl -l | grep execve" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep execve" "SV-260648r958730_rule")
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
print_rule_result "$rule_result" "SV-260648r958730_rule" "Ubuntu 22.04 LTS must prevent all software from executing at higher privilege levels than users executing the software and the audit system must be configured to audit the execution of privileged functions."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260648r958730_rule", "$stig_result", "auditctl -l | grep execve", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260649r986298_rule: Ubuntu 22.04 LTS must generate audit records for privileged activities, nonlocal maintenance, diagnostic sessions and other system-level access.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260649r986298_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must generate audit records for privileged activities, nonlocal maintenance, diagnostic sessions and other system-level access."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} generic\n"

# Check Content:
cat << 'EOF'
Verify Ubuntu 22.04 LTS audits activities performed during nonlocal maintenance and diagnostic sessions by using the following command:  
  
     $ sudo auditctl -l | grep sudo.log  
     -w /var/log/sudo.log -p wa -k maintenance  
  
If the command does not return lines that match the example or the lines are commented out, this is a finding.  
  
Note: The "-k" value is arbitrary and can be different from the example output above.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} auditctl -l | grep sudo.log"
output_0=$(eval "auditctl -l | grep sudo.log" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "auditctl -l | grep sudo.log" "SV-260649r986298_rule")
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
print_rule_result "$rule_result" "SV-260649r986298_rule" "Ubuntu 22.04 LTS must generate audit records for privileged activities, nonlocal maintenance, diagnostic sessions and other system-level access."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260649r986298_rule", "$stig_result", "auditctl -l | grep sudo.log", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

update_counters "$rule_result"

# --------------------------------------------------------------------------------
# Check for SV-260650r987791_rule: Ubuntu 22.04 LTS must implement NIST FIPS-validated cryptography to protect classified information and for the following: To provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.
# --------------------------------------------------------------------------------
echo -e "\n${CYAN}=== Checking SV-260650r987791_rule ===${NC}"
echo -e "${BLUE}Title:${NC} Ubuntu 22.04 LTS must implement NIST FIPS-validated cryptography to protect classified information and for the following: To provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards."
echo -e "${BLUE}Requirement Type:${NC} positive"
echo -e "${BLUE}Check Type:${NC} config\n"

# Check Content:
cat << 'EOF'
Verify the system is configured to run in FIPS mode by using the following command:  
  
     $ grep -i 1 /proc/sys/crypto/fips_enabled 
     1  
  
If a value of "1" is not returned, this is a finding.
EOF

echo ""


# Execute commands and evaluate results
rule_result="PASS"  # Start with assumption of pass

# Command 1
echo -e "${BLUE}Executing:${NC} grep -i 1 /proc/sys/crypto/fips_enabled"
output_0=$(eval "grep -i 1 /proc/sys/crypto/fips_enabled" 2>&1)
exit_code_0=$?
echo -e "${BLUE}Exit Code:${NC} $exit_code_0"
echo -e "${BLUE}Output:${NC}"
echo "$output_0"
echo ""

# Evaluate command result using function
cmd_result_0=$(evaluate_command_result "$exit_code_0" "$output_0" "positive" "grep -i 1 /proc/sys/crypto/fips_enabled" "SV-260650r987791_rule")
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
print_rule_result "$rule_result" "SV-260650r987791_rule" "Ubuntu 22.04 LTS must implement NIST FIPS-validated cryptography to protect classified information and for the following: To provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards."

# Output the result to CSV
stig_result=""
if [ "$rule_result" == "FAIL" ]; then
    stig_result="Open"
elif [ "$rule_result" == "PASS" ]; then
    stig_result="Not a Finding"
elif [ "$rule_result" == "MANUAL" ]; then
    stig_result="Not Reviewed"
elif [ "$rule_result" == "NOT_CHECKED" ]; then
    stig_result="Not Reviewed"
fi

# Append or create output CSV file
if [ -f output.csv ]; then
    cat << EOF >> output.csv
"SV-260650r987791_rule", "$stig_result", "grep -i 1 /proc/sys/crypto/fips_enabled", "$output_0"
EOF
else
    echo -e \"Rule ID\", \"Status\", \"Comments\", \"Finding Details\" > output.csv
fi

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
