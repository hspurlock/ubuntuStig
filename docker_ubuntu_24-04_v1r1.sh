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
# SV-270647r1066430_rule: [DOCKER] Ubuntu 24.04 LTS must not have the telnet package installed.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-270647r1066430_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 24.04 LTS must not have the telnet package installed.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_270647r1066430_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify the telnet package is not installed on Ubuntu 24.04 LTS with the following command: 
    #  
    # $ dpkg -l | grep telnetd 
    # 
    # If the telnetd package is installed, this is a finding.

    # Execute command: dpkg -l | grep telnetd
    echo -e "${CYAN}Executing: dpkg -l | grep telnetd${NC}"
    output=$(dpkg -l | grep telnetd 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "negative" "dpkg -l | grep telnetd" "SV-270647r1066430_rule")
    
    # Print result
    print_rule_result "$result" "SV-270647r1066430_rule" "[DOCKER] Ubuntu 24.04 LTS must not have the telnet package installed."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_270647r1066430_rule


# =======================================================================
# SV-270648r1066433_rule: [DOCKER] Ubuntu 24.04 LTS must not have the rsh-server package installed.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-270648r1066433_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 24.04 LTS must not have the rsh-server package installed.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_270648r1066433_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify the rsh-server package is installed with the following command: 
    #  
    # $ dpkg -l | grep rsh-server 
    #  
    # If the rsh-server package is installed, this is a finding.

    # Execute command: dpkg -l | grep rsh-server
    echo -e "${CYAN}Executing: dpkg -l | grep rsh-server${NC}"
    output=$(dpkg -l | grep rsh-server 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "negative" "dpkg -l | grep rsh-server" "SV-270648r1066433_rule")
    
    # Print result
    print_rule_result "$result" "SV-270648r1066433_rule" "[DOCKER] Ubuntu 24.04 LTS must not have the rsh-server package installed."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_270648r1066433_rule


# =======================================================================
# SV-270691r1066562_rule: [DOCKER] Ubuntu 24.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting access to via an SSH logon.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-270691r1066562_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 24.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting access to via an SSH logon.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_270691r1066562_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify Ubuntu 24.04 LTS displays the Standard Mandatory DOD Notice and Consent Banner before granting access via an SSH logon with the following command: 
    #  
    # $ sudo grep -ir banner /etc/ssh/sshd_config* 
    # /etc/ssh/sshd_config:Banner /etc/issue.net
    #  
    # The command will return the banner option along with the name of the file that contains the SSH banner. If the line is commented out, missing, or conflicting results are returned, this is a finding.
    #  
    # Verify the specified banner file matches the Standard Mandatory DOD Notice and Consent Banner exactly: 
    #  
    # $ cat /etc/issue.net 
    # "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 
    #  
    # By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
    #  
    # -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
    #  
    # -At any time, the USG may inspect and seize data stored on this IS. 
    #  
    # -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
    #  
    # -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 
    #  
    # -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." 
    #  
    # If the banner text does not match the Standard Mandatory DOD Notice and Consent Banner exactly, this is a finding.

    # Check if SSH is installed first
    if ! dpkg -l | grep -q openssh-server; then
        # SSH is not installed, so this check is not applicable
        result="NOT_CHECKED"
        echo -e "${YELLOW}SSH is not installed, skipping this check${NC}"
    else

        # Execute command: grep -ir banner /etc/ssh/sshd_config*
        echo -e "${CYAN}Executing: grep -ir banner /etc/ssh/sshd_config*${NC}"
        output=$(grep -ir banner /etc/ssh/sshd_config* 2>&1)
        exit_code=$?
        echo "$output"
        
        # Evaluate result
        result=$(evaluate_command_result "$exit_code" "$output" "positive" "grep -ir banner /etc/ssh/sshd_config*" "SV-270691r1066562_rule")
    
        # Execute command: cat /etc/issue.net
        echo -e "${CYAN}Executing: cat /etc/issue.net${NC}"
        output=$(cat /etc/issue.net 2>&1)
        exit_code=$?
        echo "$output"
        
        # Evaluate result
        result=$(evaluate_command_result "$exit_code" "$output" "positive" "cat /etc/issue.net" "SV-270691r1066562_rule")
    
    fi

    # Print result
    print_rule_result "$result" "SV-270691r1066562_rule" "[DOCKER] Ubuntu 24.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting access to via an SSH logon."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_270691r1066562_rule


# =======================================================================
# SV-270694r1066571_rule: [DOCKER] Ubuntu 24.04 LTS must be configured to enforce the acknowledgement of the Standard Mandatory DOD Notice and Consent Banner for all SSH connections.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-270694r1066571_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 24.04 LTS must be configured to enforce the acknowledgement of the Standard Mandatory DOD Notice and Consent Banner for all SSH connections.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_270694r1066571_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify Ubuntu 24.04 LTS is configured to prompt a user to acknowledge the Standard Mandatory DOD Notice and Consent Banner before granting access with the following command:
    # 
    # $ less /etc/profile.d/ssh_confirm.sh
    # #!/bin/bash
    # 
    # if [ -n "$SSH_CLIENT" ] || [ -n "$SSH_TTY" ]; then
    #         while true; do
    #                 read -p " 
    # 
    # 
    # You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
    # 
    # By using this IS (which includes any device attached to this IS), you consent to the following conditions:
    # 
    # -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
    # 
    # -At any time, the USG may inspect and seize data stored on this IS.
    # 
    # -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
    # 
    # -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
    # 
    # -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
    # 
    # Do you agree? [y/N] " yn
    #                 case $yn in
    #                         [Yy]* ) break ;;
    #                         [Nn]* ) exit 1 ;;
    #                 esac
    #         done
    # fi
    # 
    # If the output does not match the text above, this is a finding.

    # Check if SSH is installed first
    if ! dpkg -l | grep -q openssh-server; then
        # SSH is not installed, so this check is not applicable
        result="NOT_CHECKED"
        echo -e "${YELLOW}SSH is not installed, skipping this check${NC}"
    else

        # Execute command: less /etc/profile.d/ssh_confirm.sh
        echo -e "${CYAN}Executing: less /etc/profile.d/ssh_confirm.sh${NC}"
        output=$(less /etc/profile.d/ssh_confirm.sh 2>&1)
        exit_code=$?
        echo "$output"
        
        # Evaluate result
        result=$(evaluate_command_result "$exit_code" "$output" "positive" "less /etc/profile.d/ssh_confirm.sh" "SV-270694r1066571_rule")
    
    fi

    # Print result
    print_rule_result "$result" "SV-270694r1066571_rule" "[DOCKER] Ubuntu 24.04 LTS must be configured to enforce the acknowledgement of the Standard Mandatory DOD Notice and Consent Banner for all SSH connections."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_270694r1066571_rule


# =======================================================================
# SV-270701r1066592_rule: [DOCKER] Ubuntu 24.04 LTS must have system commands set to a mode of 0755 or less permissive.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-270701r1066592_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 24.04 LTS must have system commands set to a mode of 0755 or less permissive.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_270701r1066592_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify the system commands contained in the following directories have mode 0755 or less permissive with the following command: 
    #  
    # $ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c "%n %a" '{}' \; 
    #  
    # If any files are found to be group-writable or world-writable, this is a finding.

    # Execute command: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c "%n %a" '{}' \;
    echo -e "${CYAN}Executing: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c "%n %a" '{}' \;${NC}"
    output=$(find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c "%n %a" '{}' \; 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c "%n %a" '{}' \;" "SV-270701r1066592_rule")
    
    # Print result
    print_rule_result "$result" "SV-270701r1066592_rule" "[DOCKER] Ubuntu 24.04 LTS must have system commands set to a mode of 0755 or less permissive."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_270701r1066592_rule


# =======================================================================
# SV-270702r1066595_rule: [DOCKER] Ubuntu 24.04 LTS must have system commands owned by root or a system account.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-270702r1066595_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 24.04 LTS must have system commands owned by root or a system account.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_270702r1066595_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify the system commands contained in the following directories are owned by root, or a required system account, with the following command: 
    #  
    # $ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c "%n %U" '{}' \; 
    #  
    # If any system commands are returned and not owned by a required system account, this is a finding.

    # Execute command: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c "%n %U" '{}' \;
    echo -e "${CYAN}Executing: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c "%n %U" '{}' \;${NC}"
    output=$(find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c "%n %U" '{}' \; 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c "%n %U" '{}' \;" "SV-270702r1066595_rule")
    
    # Print result
    print_rule_result "$result" "SV-270702r1066595_rule" "[DOCKER] Ubuntu 24.04 LTS must have system commands owned by root or a system account."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_270702r1066595_rule


# =======================================================================
# SV-270713r1066628_rule: [DOCKER] Ubuntu 24.04 LTS must not have accounts configured with blank or null passwords.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-270713r1066628_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 24.04 LTS must not have accounts configured with blank or null passwords.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_270713r1066628_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Check the "/etc/shadow" file for blank passwords with the following command:
    # 
    # $ sudo awk -F: '!$2 {print $1}' /etc/shadow
    # 
    # If the command returns any results, this is a finding.

    # Execute command: awk -F: '!$2 {print $1}' /etc/shadow
    echo -e "${CYAN}Executing: awk -F: '!$2 {print $1}' /etc/shadow${NC}"
    output=$(awk -F: '!$2 {print $1}' /etc/shadow 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "positive" "awk -F: '!$2 {print $1}' /etc/shadow" "SV-270713r1066628_rule")
    
    # Print result
    print_rule_result "$result" "SV-270713r1066628_rule" "[DOCKER] Ubuntu 24.04 LTS must not have accounts configured with blank or null passwords."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_270713r1066628_rule


# =======================================================================
# SV-270717r1067177_rule: [DOCKER] Ubuntu 24.04 LTS must not allow unattended or automatic login via SSH.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-270717r1067177_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 24.04 LTS must not allow unattended or automatic login via SSH.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_270717r1067177_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify unattended or automatic login via SSH is disabled with the following command:
    # 
    # $ egrep -r '(Permit(.*?)(Passwords|Environment))' /etc/ssh/sshd_config
    # PermitEmptyPasswords no
    # PermitUserEnvironment no
    # 
    # If the "PermitEmptyPasswords" or "PermitUserEnvironment" keywords are set to a value other than "no", are commented out, are both missing, or conflicting results are returned, this is a finding.

    # Check if SSH is installed first
    if ! dpkg -l | grep -q openssh-server; then
        # SSH is not installed, so this check is not applicable
        result="NOT_CHECKED"
        echo -e "${YELLOW}SSH is not installed, skipping this check${NC}"
    else

        # Execute command: egrep -r '(Permit(.*?)(Passwords|Environment))' /etc/ssh/sshd_config
        echo -e "${CYAN}Executing: egrep -r '(Permit(.*?)(Passwords|Environment))' /etc/ssh/sshd_config${NC}"
        output=$(egrep -r '(Permit(.*?)(Passwords|Environment))' /etc/ssh/sshd_config 2>&1)
        exit_code=$?
        echo "$output"
        
        # Evaluate result
        result=$(evaluate_command_result "$exit_code" "$output" "positive" "egrep -r '(Permit(.*?)(Passwords|Environment))' /etc/ssh/sshd_config" "SV-270717r1067177_rule")
    
    fi

    # Print result
    print_rule_result "$result" "SV-270717r1067177_rule" "[DOCKER] Ubuntu 24.04 LTS must not allow unattended or automatic login via SSH."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_270717r1067177_rule


# =======================================================================
# SV-270720r1066649_rule: [DOCKER] Ubuntu 24.04 LTS must uniquely identify interactive users.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-270720r1066649_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 24.04 LTS must uniquely identify interactive users.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_270720r1066649_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify Ubuntu 24.04 LTS contains no duplicate User IDs (UIDs) for interactive users with the following command: 
    #  
    # $ awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd 
    #  
    # If output is produced and the accounts listed are interactive user accounts, this is a finding.

    # Execute command: awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd
    echo -e "${CYAN}Executing: awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd${NC}"
    output=$(awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "positive" "awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd" "SV-270720r1066649_rule")
    
    # Print result
    print_rule_result "$result" "SV-270720r1066649_rule" "[DOCKER] Ubuntu 24.04 LTS must uniquely identify interactive users."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_270720r1066649_rule


# =======================================================================
# SV-270722r1067130_rule: [DOCKER] Ubuntu 24.04 LTS must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts over SSH.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-270722r1067130_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 24.04 LTS must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts over SSH.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_270722r1067130_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify the sshd daemon allows public key authentication with the following command:
    #  
    # $ sudo grep -r ^PubkeyAuthentication /etc/ssh/sshd_config*
    # /etc/ssh/sshd_config:PubkeyAuthentication yes
    # 
    # If "PubkeyAuthentication" is not set to "yes", is commented out, is missing, or conflicting results are returned, this is a finding.

    # Check if SSH is installed first
    if ! dpkg -l | grep -q openssh-server; then
        # SSH is not installed, so this check is not applicable
        result="NOT_CHECKED"
        echo -e "${YELLOW}SSH is not installed, skipping this check${NC}"
    else

        # Execute command: grep -r ^PubkeyAuthentication /etc/ssh/sshd_config*
        echo -e "${CYAN}Executing: grep -r ^PubkeyAuthentication /etc/ssh/sshd_config*${NC}"
        output=$(grep -r ^PubkeyAuthentication /etc/ssh/sshd_config* 2>&1)
        exit_code=$?
        echo "$output"
        
        # Evaluate result
        result=$(evaluate_command_result "$exit_code" "$output" "positive" "grep -r ^PubkeyAuthentication /etc/ssh/sshd_config*" "SV-270722r1067130_rule")
    
    fi

    # Print result
    print_rule_result "$result" "SV-270722r1067130_rule" "[DOCKER] Ubuntu 24.04 LTS must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts over SSH."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_270722r1067130_rule


# =======================================================================
# SV-270741r1066712_rule: [DOCKER] Ubuntu 24.04 LTS must use strong authenticators in establishing nonlocal maintenance and diagnostic sessions.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-270741r1066712_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 24.04 LTS must use strong authenticators in establishing nonlocal maintenance and diagnostic sessions.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_270741r1066712_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify Ubuntu 24.04 LTS is configured to use strong authenticators in the establishment of nonlocal maintenance and diagnostic maintenance with the following command:
    # 
    # $ sudo grep -r ^UsePAM /etc/ssh/sshd_config*
    # /etc/ssh/sshd_config:UsePAM yes
    # 
    # If "UsePAM" is not set to "yes", conflicting results are returned, the line is commented out, or is missing, this is a finding.

    # Execute command: grep -r ^UsePAM /etc/ssh/sshd_config*
    echo -e "${CYAN}Executing: grep -r ^UsePAM /etc/ssh/sshd_config*${NC}"
    output=$(grep -r ^UsePAM /etc/ssh/sshd_config* 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "positive" "grep -r ^UsePAM /etc/ssh/sshd_config*" "SV-270741r1066712_rule")
    
    # Print result
    print_rule_result "$result" "SV-270741r1066712_rule" "[DOCKER] Ubuntu 24.04 LTS must use strong authenticators in establishing nonlocal maintenance and diagnostic sessions."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_270741r1066712_rule


# =======================================================================
# SV-270742r1066715_rule: [DOCKER] Ubuntu 24.04 LTS must immediately terminate all network connections associated with SSH traffic after a period of inactivity.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-270742r1066715_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 24.04 LTS must immediately terminate all network connections associated with SSH traffic after a period of inactivity.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_270742r1066715_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify that all network connections associated with SSH traffic automatically terminate after a period of inactivity with the following command: 
    # 
    # $ sudo grep -ir ClientAliveCountMax /etc/ssh/sshd_config*
    # /etc/ssh/sshd_config:ClientAliveCountMax  1
    # 
    # If "ClientAliveCountMax" is not to "1", if conflicting results are returned, is commented out, or is missing, this is a finding.

    # Check if SSH is installed first
    if ! dpkg -l | grep -q openssh-server; then
        # SSH is not installed, so this check is not applicable
        result="NOT_CHECKED"
        echo -e "${YELLOW}SSH is not installed, skipping this check${NC}"
    else

        # Execute command: grep -ir ClientAliveCountMax /etc/ssh/sshd_config*
        echo -e "${CYAN}Executing: grep -ir ClientAliveCountMax /etc/ssh/sshd_config*${NC}"
        output=$(grep -ir ClientAliveCountMax /etc/ssh/sshd_config* 2>&1)
        exit_code=$?
        echo "$output"
        
        # Evaluate result
        result=$(evaluate_command_result "$exit_code" "$output" "positive" "grep -ir ClientAliveCountMax /etc/ssh/sshd_config*" "SV-270742r1066715_rule")
    
    fi

    # Print result
    print_rule_result "$result" "SV-270742r1066715_rule" "[DOCKER] Ubuntu 24.04 LTS must immediately terminate all network connections associated with SSH traffic after a period of inactivity."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_270742r1066715_rule


# =======================================================================
# SV-270743r1066718_rule: [DOCKER] Ubuntu 24.04 LTS must immediately terminate all network connections associated with SSH traffic at the end of the session or after 10 minutes of inactivity.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-270743r1066718_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 24.04 LTS must immediately terminate all network connections associated with SSH traffic at the end of the session or after 10 minutes of inactivity.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_270743r1066718_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify that all network connections associated with SSH traffic are automatically terminated at the end of the session or after 10 minutes of inactivity with the following command:
    # 
    # $ grep -ir ClientAliveInterval /etc/ssh/sshd_config*
    # /etc/ssh/sshd_config:ClientAliveInterval 600
    # 
    # If "ClientAliveInterval" does not exist, is not set to a value of "600" or less in "/etc/ssh/sshd_config", if conflicting results are returned, is commented out, or is missing, this is a finding.

    # Check if SSH is installed first
    if ! dpkg -l | grep -q openssh-server; then
        # SSH is not installed, so this check is not applicable
        result="NOT_CHECKED"
        echo -e "${YELLOW}SSH is not installed, skipping this check${NC}"
    else

        # Execute command: grep -ir ClientAliveInterval /etc/ssh/sshd_config*
        echo -e "${CYAN}Executing: grep -ir ClientAliveInterval /etc/ssh/sshd_config*${NC}"
        output=$(grep -ir ClientAliveInterval /etc/ssh/sshd_config* 2>&1)
        exit_code=$?
        echo "$output"
        
        # Evaluate result
        result=$(evaluate_command_result "$exit_code" "$output" "positive" "grep -ir ClientAliveInterval /etc/ssh/sshd_config*" "SV-270743r1066718_rule")
    
    fi

    # Print result
    print_rule_result "$result" "SV-270743r1066718_rule" "[DOCKER] Ubuntu 24.04 LTS must immediately terminate all network connections associated with SSH traffic at the end of the session or after 10 minutes of inactivity."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_270743r1066718_rule


# =======================================================================
# SV-270750r1066739_rule: [DOCKER] Ubuntu 24.04 LTS must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-270750r1066739_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 24.04 LTS must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_270750r1066739_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify all public (world-writeable) directories have the public sticky bit set with the following command:  
    #  
    # $ sudo find / -type d -perm -002 ! -perm -1000 
    #  
    # If any world-writable directories are found missing the sticky bit, this is a finding.

    # Execute command: find / -type d -perm -002 ! -perm -1000
    echo -e "${CYAN}Executing: find / -type d -perm -002 ! -perm -1000${NC}"
    output=$(find / -type d -perm -002 ! -perm -1000 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "positive" "find / -type d -perm -002 ! -perm -1000" "SV-270750r1066739_rule")
    
    # Print result
    print_rule_result "$result" "SV-270750r1066739_rule" "[DOCKER] Ubuntu 24.04 LTS must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_270750r1066739_rule


# =======================================================================
# SV-270824r1066961_rule: [DOCKER] Ubuntu 24.04 LTS must have directories that contain system commands set to a mode of "0755" or less permissive.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-270824r1066961_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 24.04 LTS must have directories that contain system commands set to a mode of "0755" or less permissive.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_270824r1066961_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify the system commands directories have mode "0755" or less permissive with the following command: 
    #  
    # $ find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" '{}' \; 
    #  
    # If any directories are found to be group-writable or world-writable, this is a finding.

    # Execute command: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" '{}' \;
    echo -e "${CYAN}Executing: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" '{}' \;${NC}"
    output=$(find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" '{}' \; 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" '{}' \;" "SV-270824r1066961_rule")
    
    # Print result
    print_rule_result "$result" "SV-270824r1066961_rule" "[DOCKER] Ubuntu 24.04 LTS must have directories that contain system commands set to a mode of "0755" or less permissive."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_270824r1066961_rule


# =======================================================================
# SV-270825r1066964_rule: [DOCKER] Ubuntu 24.04 LTS must have directories that contain system commands owned by root.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-270825r1066964_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 24.04 LTS must have directories that contain system commands owned by root.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_270825r1066964_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify the system commands directories are owned by root with the following command: 
    #  
    # $ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' \; 
    #  
    # If any system commands directories are returned, this is a finding.

    # Execute command: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' \;
    echo -e "${CYAN}Executing: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' \;${NC}"
    output=$(find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' \; 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' \;" "SV-270825r1066964_rule")
    
    # Print result
    print_rule_result "$result" "SV-270825r1066964_rule" "[DOCKER] Ubuntu 24.04 LTS must have directories that contain system commands owned by root."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_270825r1066964_rule


# =======================================================================
# SV-270826r1066967_rule: [DOCKER] Ubuntu 24.04 LTS must have directories that contain system commands group-owned by root.
# =======================================================================
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}Checking SV-270826r1066967_rule${NC}"
echo -e "${CYAN}Title: [DOCKER] Ubuntu 24.04 LTS must have directories that contain system commands group-owned by root.${NC}"
echo -e "${CYAN}=======================================================${NC}"

check_SV_270826r1066967_rule() {
    # Check content:
    # NOTE: This check has been modified for Docker compatibility. Some aspects of the original check may not apply in a containerized environment.
    # 
    # Verify the system commands directories are group-owned by root with the following command: 
    #  
    # $ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c "%n %G" '{}' \; 
    #  
    # If any system commands directories are returned that are not Set Group ID up on execution (SGID) files and owned by a privileged account, this is a finding.

    # Execute command: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c "%n %G" '{}' \;
    echo -e "${CYAN}Executing: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c "%n %G" '{}' \;${NC}"
    output=$(find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c "%n %G" '{}' \; 2>&1)
    exit_code=$?
    echo "$output"
    
    # Evaluate result
    result=$(evaluate_command_result "$exit_code" "$output" "positive" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c "%n %G" '{}' \;" "SV-270826r1066967_rule")
    
    # Print result
    print_rule_result "$result" "SV-270826r1066967_rule" "[DOCKER] Ubuntu 24.04 LTS must have directories that contain system commands group-owned by root."
    
    # Update counters
    update_counters "$result"
}

# Run the check
check_SV_270826r1066967_rule


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
echo -e "${BLUE}Total STIG Rules:${NC} 188"
echo -e "${GREEN}Docker-Compatible Rules:${NC} 17"
echo -e "${RED}Docker-Incompatible Rules:${NC} 171"
echo -e "${CYAN}=======================================================${NC}"
