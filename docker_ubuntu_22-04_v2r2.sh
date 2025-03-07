#!/bin/bash
# Docker-Compatible Ubuntu STIG Compliance Checker
# Auto-generated script to check STIG compliance in Docker containers

# Color definitions
RED='[0;31m'
GREEN='[0;32m'
YELLOW='[0;33m'
BLUE='[0;34m'
MAGENTA='[0;35m'
CYAN='[0;36m'
NC='[0m' # No Color

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
        if [[ "$output" == *"You are accessing"* ]] &&            [[ "$output" == *"U.S. Government"* ]] &&            [[ "$output" == *"unauthorized access"* ]]; then
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
        if [[ "$output" == *"You are accessing"* ]] &&            [[ "$output" == *"U.S. Government"* ]] &&            [[ "$output" == *"unauthorized access"* ]] &&            [[ "$output" == *"ACKNOWLEDGE"* ]]; then
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

# ======================================================
# DOCKER-COMPATIBLE STIG COMPLIANCE CHECKS
# ======================================================
# This script contains only STIG checks that are compatible with Docker containers.
# Many system-level checks have been excluded as they don't apply in containerized environments.
# ======================================================


# =======================================================================
# SV-260482r958478_rule: [DOCKER] Ubuntu 22.04 LTS must not have the "rsh-server" package installed.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-260482r958478_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 22.04 LTS must not have the "rsh-server" package installed.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_260482r958478_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify the "rsh-server" package is not installed by using the following command:  
    #   
    #      $ dpkg -l | grep rsh-server 
    #   
    # If the "rsh-server" package is installed, this is a finding.

    # Execute command: dpkg -l | grep rsh-server
    echo -e "${CYAN}Executing: dpkg -l | grep rsh-server${NC}"
    output=$(dpkg -l | grep rsh-server 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "negative" "dpkg -l | grep rsh-server" "SV-260482r958478_rule")
    
    # Print result
    print_rule_result "$result" "SV-260482r958478_rule" "[DOCKER] Ubuntu 22.04 LTS must not have the "rsh-server" package installed."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_260482r958478_rule


# =======================================================================
# SV-260483r987796_rule: [DOCKER] Ubuntu 22.04 LTS must not have the "telnet" package installed.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-260483r987796_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 22.04 LTS must not have the "telnet" package installed.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_260483r987796_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify that the "telnetd" package is not installed on Ubuntu 22.04 LTS by using the following command:  
    #  
    #      $ dpkg -l | grep telnetd 
    #  
    # If the "telnetd" package is installed, this is a finding.

    # Execute command: dpkg -l | grep telnetd
    echo -e "${CYAN}Executing: dpkg -l | grep telnetd${NC}"
    output=$(dpkg -l | grep telnetd 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "negative" "dpkg -l | grep telnetd" "SV-260483r987796_rule")
    
    # Print result
    print_rule_result "$result" "SV-260483r987796_rule" "[DOCKER] Ubuntu 22.04 LTS must not have the "telnet" package installed."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_260483r987796_rule


# =======================================================================
# SV-260485r991559_rule: [DOCKER] Ubuntu 22.04 LTS must have directories that contain system commands set to a mode of "755" or less permissive.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-260485r991559_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 22.04 LTS must have directories that contain system commands set to a mode of "755" or less permissive.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_260485r991559_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify the system commands directories have mode "755" or less permissive by using the following command:  
    #   
    #      $ find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" '{}' \;  
    #   
    # If any directories are found to be group-writable or world-writable, this is a finding.

    # Execute command: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" '{}' \;
    echo -e "${CYAN}Executing: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" '{}' \;${NC}"
    output=$(find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" '{}' \; 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" '{}' \;" "SV-260485r991559_rule")
    
    # Print result
    print_rule_result "$result" "SV-260485r991559_rule" "[DOCKER] Ubuntu 22.04 LTS must have directories that contain system commands set to a mode of "755" or less permissive."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_260485r991559_rule


# =======================================================================
# SV-260486r991560_rule: [DOCKER] Ubuntu 22.04 LTS must have system commands set to a mode of "755" or less permissive.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-260486r991560_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 22.04 LTS must have system commands set to a mode of "755" or less permissive.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_260486r991560_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify the system commands contained in the following directories have mode "755" or less permissive by using the following command:  
    #   
    #      $ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c "%n %a" '{}' \; 
    #   
    # If any files are found to be group-writable or world-writable, this is a finding.

    # Execute command: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c "%n %a" '{}' \;
    echo -e "${CYAN}Executing: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c "%n %a" '{}' \;${NC}"
    output=$(find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c "%n %a" '{}' \; 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c "%n %a" '{}' \;" "SV-260486r991560_rule")
    
    # Print result
    print_rule_result "$result" "SV-260486r991560_rule" "[DOCKER] Ubuntu 22.04 LTS must have system commands set to a mode of "755" or less permissive."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_260486r991560_rule


# =======================================================================
# SV-260493r991559_rule: [DOCKER] Ubuntu 22.04 LTS must have directories that contain system commands owned by "root".
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-260493r991559_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 22.04 LTS must have directories that contain system commands owned by "root".${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_260493r991559_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify the system commands directories are owned by "root" by using the following command:  
    #   
    #      $ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' \; 
    #   
    # If any system commands directories are returned, this is a finding.

    # Execute command: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' \;
    echo -e "${CYAN}Executing: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' \;${NC}"
    output=$(find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' \; 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' \;" "SV-260493r991559_rule")
    
    # Print result
    print_rule_result "$result" "SV-260493r991559_rule" "[DOCKER] Ubuntu 22.04 LTS must have directories that contain system commands owned by "root"."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_260493r991559_rule


# =======================================================================
# SV-260494r991559_rule: [DOCKER] Ubuntu 22.04 LTS must have directories that contain system commands group-owned by "root".
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-260494r991559_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 22.04 LTS must have directories that contain system commands group-owned by "root".${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_260494r991559_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify the system commands directories are group-owned by "root" by using the following command:  
    #   
    #      $ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c "%n %G" '{}' \; 
    #   
    # If any system commands directories are returned that are not Set Group ID up on execution (SGID) files and owned by a privileged account, this is a finding.

    # Execute command: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c "%n %G" '{}' \;
    echo -e "${CYAN}Executing: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c "%n %G" '{}' \;${NC}"
    output=$(find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c "%n %G" '{}' \; 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c "%n %G" '{}' \;" "SV-260494r991559_rule")
    
    # Print result
    print_rule_result "$result" "SV-260494r991559_rule" "[DOCKER] Ubuntu 22.04 LTS must have directories that contain system commands group-owned by "root"."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_260494r991559_rule


# =======================================================================
# SV-260495r991560_rule: [DOCKER] Ubuntu 22.04 LTS must have system commands owned by "root" or a system account.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-260495r991560_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 22.04 LTS must have system commands owned by "root" or a system account.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_260495r991560_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify the system commands contained in the following directories are owned by "root", or a required system account, by using the following command:  
    #   
    #      $ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c "%n %U" '{}' \; 
    #   
    # If any system commands are returned and are not owned by a required system account, this is a finding.

    # Execute command: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c "%n %U" '{}' \;
    echo -e "${CYAN}Executing: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c "%n %U" '{}' \;${NC}"
    output=$(find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c "%n %U" '{}' \; 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c "%n %U" '{}' \;" "SV-260495r991560_rule")
    
    # Print result
    print_rule_result "$result" "SV-260495r991560_rule" "[DOCKER] Ubuntu 22.04 LTS must have system commands owned by "root" or a system account."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_260495r991560_rule


# =======================================================================
# SV-260513r958524_rule: [DOCKER] Ubuntu 22.04 LTS must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-260513r958524_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 22.04 LTS must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_260513r958524_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify that all public directories have the public sticky bit set by using the following command:   
    #   
    #      $ sudo find / -type d -perm -002 ! -perm -1000 
    #   
    # If any public directories are found missing the sticky bit, this is a finding.

    # Execute command: find / -type d -perm -002 ! -perm -1000
    echo -e "${CYAN}Executing: find / -type d -perm -002 ! -perm -1000${NC}"
    output=$(find / -type d -perm -002 ! -perm -1000 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "positive" "find / -type d -perm -002 ! -perm -1000" "SV-260513r958524_rule")
    
    # Print result
    print_rule_result "$result" "SV-260513r958524_rule" "[DOCKER] Ubuntu 22.04 LTS must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_260513r958524_rule


# =======================================================================
# SV-260543r958482_rule: [DOCKER] Ubuntu 22.04 LTS must uniquely identify interactive users.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-260543r958482_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 22.04 LTS must uniquely identify interactive users.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_260543r958482_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify Ubuntu 22.04 LTS contains no duplicate User IDs (UIDs) for interactive users by using the following command:  
    #   
    #      $ awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd 
    #   
    # If output is produced and the accounts listed are interactive user accounts, this is a finding.

    # Execute command: awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd
    echo -e "${CYAN}Executing: awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd${NC}"
    output=$(awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "positive" "awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd" "SV-260543r958482_rule")
    
    # Print result
    print_rule_result "$result" "SV-260543r958482_rule" "[DOCKER] Ubuntu 22.04 LTS must uniquely identify interactive users."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_260543r958482_rule


# =======================================================================
# SV-260548r958364_rule: [DOCKER] Ubuntu 22.04 LTS must automatically expire temporary accounts within 72 hours.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-260548r958364_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 22.04 LTS must automatically expire temporary accounts within 72 hours.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_260548r958364_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify temporary accounts have been provisioned with an expiration date of 72 hours by using the following command: 
    #  
    #      $ sudo chage -l  | grep -E '(Password|Account) expires' 
    #      Password expires     : Apr 1, 2024  
    #      Account expires        : Apr 1, 2024  
    #  
    # Verify each of these accounts has an expiration date set within 72 hours. 
    #  
    # If any temporary accounts have no expiration date set or do not expire within 72 hours, this is a finding.

    # Execute command: chage -l  | grep -E '(Password|Account) expires'
    echo -e "${CYAN}Executing: chage -l  | grep -E '(Password|Account) expires'${NC}"
    output=$(chage -l  | grep -E '(Password|Account) expires' 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "positive" "chage -l  | grep -E '(Password|Account) expires'" "SV-260548r958364_rule")
    
    # Print result
    print_rule_result "$result" "SV-260548r958364_rule" "[DOCKER] Ubuntu 22.04 LTS must automatically expire temporary accounts within 72 hours."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_260548r958364_rule


# =======================================================================
# SV-260571r991589_rule: [DOCKER] Ubuntu 22.04 LTS must not have accounts configured with blank or null passwords.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-260571r991589_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 22.04 LTS must not have accounts configured with blank or null passwords.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_260571r991589_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify all accounts on the system to have a password by using the following command: 
    #  
    #      $ sudo awk -F: '!$2 {print $1}' /etc/shadow 
    #  
    # If the command returns any results, this is a finding.

    # Execute command: awk -F: '!$2 {print $1}' /etc/shadow
    echo -e "${CYAN}Executing: awk -F: '!$2 {print $1}' /etc/shadow${NC}"
    output=$(awk -F: '!$2 {print $1}' /etc/shadow 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "positive" "awk -F: '!$2 {print $1}' /etc/shadow" "SV-260571r991589_rule")
    
    # Print result
    print_rule_result "$result" "SV-260571r991589_rule" "[DOCKER] Ubuntu 22.04 LTS must not have accounts configured with blank or null passwords."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_260571r991589_rule


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

# ======================================================
# DOCKER COMPATIBILITY SUMMARY
# ======================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}       Docker Compatibility Summary                   ${NC}"
echo -e "${CYAN}=======================================================${NC}"
echo -e "${BLUE}Total STIG Rules:${NC} 180"
echo -e "${GREEN}Docker-Compatible Rules:${NC} 11"
echo -e "${RED}Docker-Incompatible Rules:${NC} 169"
echo -e "${CYAN}=======================================================${NC}"
