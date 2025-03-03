#!/bin/bash

# Script to run a single STIG check from the compliance script
# Usage: sudo ./run_single_check.sh <rule_id> <xml_file> [debug]

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} This script must be run as root to perform all checks properly."
    echo "Please run with: sudo $0 <rule_id> <xml_file> [debug]"
    exit 1
fi

# Check if rule_id is provided
if [ -z "$1" ]; then
    echo -e "${RED}[ERROR]${NC} Please provide a rule ID to check."
    echo "Usage: sudo $0 <rule_id> <xml_file> [debug]"
    exit 1
fi

# Check if XML file is provided
if [ -z "$2" ]; then
    echo -e "${RED}[ERROR]${NC} No XML file provided"
    echo "Usage: sudo $0 <rule_id> <xml_file> [debug]"
    exit 1
fi

RULE_ID="$1"
XML_FILE="$2"
DEBUG=${3:-false}

# Set colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}[DEBUG]${NC} Using XML file: $XML_FILE"

# Extract rule information from XML
RULE_TITLE=$(python3 parse_stig_xml.py "$XML_FILE" "$RULE_ID" "title")
CHECK_CONTENT=$(python3 parse_stig_xml.py "$XML_FILE" "$RULE_ID" "check_content")
COMMANDS_JSON=$(python3 parse_stig_xml.py "$XML_FILE" "$RULE_ID" "commands")

echo -e "${BLUE}[INFO]${NC} Checking rule: $RULE_TITLE"

# Determine if this is a negative requirement
if is_negative_requirement "$RULE_TITLE"; then
    echo -e "${BLUE}[INFO]${NC} This is a negative requirement"
    NEGATIVE=true
else
    NEGATIVE=false
fi

# Debug output
if [[ "$DEBUG" == "true" ]]; then
    echo -e "${BLUE}[DEBUG]${NC} Rule ID: $RULE_ID"
    echo -e "${BLUE}[DEBUG]${NC} Rule Title: $RULE_TITLE"
    echo -e "${BLUE}[DEBUG]${NC} Check Content: $CHECK_CONTENT"
    echo -e "${BLUE}[DEBUG]${NC} Commands: $COMMANDS_JSON"
    echo -e "${BLUE}[DEBUG]${NC} Negative Requirement: $NEGATIVE"
fi

# Create a directory for command tracking
CMD_DIR=$(mktemp -d)

# Execute commands and evaluate results
OVERALL_RESULT=0
COMMAND_COUNT=0
COMMAND_RESULTS=()
COMMAND_OUTPUTS=()
COMMAND_EXIT_CODES=()
COMMAND_EVAL_RESULTS=()

# Function to execute commands and track their execution
execute_command() {
    local cmd="$1"
    
    # Execute the command and capture output
    output=$(eval "$cmd" 2>&1)
    exit_code=$?
    
    return $exit_code
}

# Function to evaluate command results based on command type and output
evaluate_command_result() {
    local cmd="$1"
    local exit_code="$2"
    local negative="$3"
    
    # Default to using the original exit code
    local result_code=$exit_code
    
    # Handle dpkg commands with grep first (most specific case)
    if [[ "$cmd" == *"dpkg -l"* && "$cmd" == *"grep"* ]]; then
        # Extract the package name from the command
        local pkg_name=$(echo "$cmd" | grep -o "grep [^ ]*" | awk '{print $2}')
        
        # For dpkg -l | grep commands:
        # Exit code 0 = package is installed and found
        # Exit code 1 = package not found (could be not installed or just not matching grep)
        
        if [ $exit_code -eq 0 ]; then
            # Package is installed
            if [ "$negative" = true ]; then
                echo -e "${RED}[FAIL]${NC} Package $pkg_name is installed but should not be."
                result_code=1
            else
                echo -e "${GREEN}[PASS]${NC} Package $pkg_name is installed as required."
                result_code=0
            fi
        elif [ $exit_code -eq 1 ]; then
            # Package not found
            if [ "$negative" = true ]; then
                echo -e "${GREEN}[PASS]${NC} Package $pkg_name is not installed as required."
                result_code=0
            else
                echo -e "${RED}[FAIL]${NC} Package $pkg_name is not installed but should be."
                result_code=1
            fi
        else
            # Other error
            echo -e "${RED}[FAIL]${NC} Error checking package $pkg_name, exit code $exit_code"
            result_code=1
        fi
        
        # Return early to avoid other checks
        return $result_code
    # Handle grep commands specially
    elif [[ "$cmd" == *"grep"* ]]; then
        # For grep commands, exit code 2 means error (like file not found)
        # but we should only fail if we find a problematic pattern
        if [ $exit_code -eq 2 ]; then
            # Check if this is a configuration check (looking for settings)
            if [[ "$cmd" == *"sysctl"* || "$cmd" == */etc/sysctl* || "$cmd" == */sysctl.d* ]]; then
                # Extract the setting name from the command
                local setting_name=""
                if [[ "$cmd" == *"grep"*"kernel.dmesg_restrict"* ]]; then
                    setting_name="kernel.dmesg_restrict"
                elif [[ "$cmd" == *"grep"*"kernel.randomize_va_space"* ]]; then
                    setting_name="kernel.randomize_va_space"
                elif [[ "$cmd" == *"grep"*"kernel.yama.ptrace_scope"* ]]; then
                    setting_name="kernel.yama.ptrace_scope"
                elif [[ "$cmd" == *"grep"*"net.ipv4.conf.all.send_redirects"* ]]; then
                    setting_name="net.ipv4.conf.all.send_redirects"
                elif [[ "$cmd" == *"grep"*"net.ipv4.conf.default.send_redirects"* ]]; then
                    setting_name="net.ipv4.conf.default.send_redirects"
                elif [[ "$cmd" == *"grep"*"net.ipv4.ip_forward"* ]]; then
                    setting_name="net.ipv4.ip_forward"
                fi
                
                # Determine the expected value based on the setting
                local expected_value="1"  # Default for most security settings (enabled)
                local bad_value="0"
                
                # Settings that should be 0 (disabled) for security
                if [[ "$setting_name" == "net.ipv4.conf.all.send_redirects" || 
                      "$setting_name" == "net.ipv4.conf.default.send_redirects" ||
                      "$setting_name" == "net.ipv4.ip_forward" ]]; then
                    expected_value="0"
                    bad_value="1"
                fi
                
                # If we're checking a negative requirement, flip the expected values
                if [[ "$negative" == "true" ]]; then
                    local temp="$expected_value"
                    expected_value="$bad_value"
                    bad_value="$temp"
                fi
                
                # Check if output contains any uncommented lines with problematic settings
                if echo "$output" | grep -v "^#" | grep -v "^[^:]*:#" | grep -q "$setting_name.*=.*$bad_value"; then
                    echo -e "${RED}[FAIL]${NC} Found uncommented problematic configuration setting"
                    result_code=1
                else
                    echo -e "${GREEN}[PASS]${NC} No uncommented problematic configuration settings found"
                    result_code=0
                fi
            else
                # For other grep checks, treat exit code 2 differently based on requirement type
                if [[ "$negative" == "true" ]]; then
                    # For negative requirements, file not found is good
                    echo -e "${YELLOW}[INFO]${NC} Grep command returned error code 2 (file not found), treating as success for negative requirement"
                    result_code=0
                else
                    # For positive requirements, file not found is bad
                    echo -e "${YELLOW}[INFO]${NC} Grep command returned error code 2 (file not found), treating as failure for positive requirement"
                    result_code=1
                fi
            fi
        elif [ $exit_code -eq 1 ]; then
            # Exit code 1 means no matches found
            # This could be good or bad depending on the check
            if [[ "$negative" == "true" ]]; then
                # For negative requirements, no matches is good
                echo -e "${GREEN}[PASS]${NC} No matches found (expected for negative requirement)"
                result_code=0
            else
                # For positive requirements, we need to check the context
                if [[ "$cmd" == *"! grep"* || "$cmd" == *"grep -v"* ]]; then
                    # If using negated grep, no matches is good
                    echo -e "${GREEN}[PASS]${NC} No matches found (expected for negated grep)"
                    result_code=0
                fi
                # Otherwise, keep the exit code 1 (failure)
            fi
        fi
    # Handle dpkg commands without grep
    elif [[ "$cmd" == *"dpkg -l"* || "$cmd" == *"dpkg-query"* ]] && [[ "$cmd" != *"grep"* ]]; then
        # Extract the package name from the command
        local pkg_name=""
        if [[ "$cmd" =~ dpkg\ -l\ ([^ ]+) ]]; then
            pkg_name="${BASH_REMATCH[1]}"
        fi
        
        # If exit code is 0, the package is installed
        if [ $exit_code -eq 0 ]; then
            if [ "$negative" = true ]; then
                echo -e "${RED}[FAIL]${NC} Package $pkg_name is installed but should not be."
                result_code=1
            else
                echo -e "${GREEN}[PASS]${NC} Package $pkg_name is installed as required."
                result_code=0
            fi
        else
            # Exit code is non-zero, package not installed
            if [ "$negative" = true ]; then
                echo -e "${GREEN}[PASS]${NC} Package $pkg_name is not installed as required."
                result_code=0
            else
                echo -e "${RED}[FAIL]${NC} Package $pkg_name is not installed but should be."
                result_code=1
            fi
        fi
    # Handle sysctl commands
    elif [[ "$cmd" == *"sysctl"* && ! "$cmd" == *"grep"* ]]; then
        # Extract the setting name from the command
        local setting_name=""
        if [[ "$cmd" == *"kernel.dmesg_restrict"* ]]; then
            setting_name="kernel.dmesg_restrict"
        elif [[ "$cmd" == *"kernel.randomize_va_space"* ]]; then
            setting_name="kernel.randomize_va_space"
        elif [[ "$cmd" == *"kernel.yama.ptrace_scope"* ]]; then
            setting_name="kernel.yama.ptrace_scope"
        elif [[ "$cmd" == *"net.ipv4.conf.all.send_redirects"* ]]; then
            setting_name="net.ipv4.conf.all.send_redirects"
        elif [[ "$cmd" == *"net.ipv4.conf.default.send_redirects"* ]]; then
            setting_name="net.ipv4.conf.default.send_redirects"
        elif [[ "$cmd" == *"net.ipv4.ip_forward"* ]]; then
            setting_name="net.ipv4.ip_forward"
        fi
        
        # Determine the expected value based on the setting
        local expected_value="1"  # Default for most security settings (enabled)
        
        # Settings that should be 0 (disabled) for security
        if [[ "$setting_name" == "net.ipv4.conf.all.send_redirects" || 
              "$setting_name" == "net.ipv4.conf.default.send_redirects" ||
              "$setting_name" == "net.ipv4.ip_forward" ]]; then
            expected_value="0"
        fi
        
        # If we're checking a negative requirement, flip the expected value
        if [[ "$negative" == "true" ]]; then
            expected_value=$(( 1 - expected_value ))
        fi
        
        # For sysctl commands, check if the output matches expected values
        if [[ "$expected_value" == "1" ]]; then
            if [[ "$output" == *"= 1"* || "$output" == *"= on"* || "$output" == *"= yes"* || "$output" == *"= true"* ]]; then
                echo -e "${GREEN}[PASS]${NC} Sysctl setting $setting_name is correctly set to $expected_value"
                result_code=0
            else
                echo -e "${RED}[FAIL]${NC} Sysctl setting $setting_name is not set to $expected_value"
                result_code=1
            fi
        else
            if [[ "$output" == *"= 0"* || "$output" == *"= off"* || "$output" == *"= no"* || "$output" == *"= false"* ]]; then
                echo -e "${GREEN}[PASS]${NC} Sysctl setting $setting_name is correctly set to $expected_value"
                result_code=0
            else
                echo -e "${RED}[FAIL]${NC} Sysctl setting $setting_name is not set to $expected_value"
                result_code=1
            fi
        fi
    fi
    
    return $result_code
}

# Function to determine if a rule has a negative requirement
is_negative_requirement() {
    local title="$1"
    
    # Check for negative language in the title
    if [[ "$title" == *"must not"* ]] || 
       [[ "$title" == *"must be disabled"* ]] || 
       [[ "$title" == *"must be removed"* ]] ||
       [[ "$title" == *"must not be installed"* ]]; then
        return 0  # True, it is a negative requirement
    else
        return 1  # False, it is not a negative requirement
    fi
}

# Parse commands from JSON
while IFS= read -r cmd; do
    if [ -n "$cmd" ]; then
        echo -e "${YELLOW}[EXECUTING]${NC} $cmd"
        
        # Execute the command and capture output and exit code
        output=$(execute_command "$cmd")
        exit_code=$?
        
        echo "Command exit code: $exit_code"
        if [ -z "$output" ]; then
            echo "No output from command"
        else
            echo "$output"
        fi
        
        # Store command results for later reporting
        COMMAND_RESULTS+=("$cmd")
        COMMAND_OUTPUTS+=("$output")
        COMMAND_EXIT_CODES+=("$exit_code")
        
        # Evaluate the command result
        evaluate_command_result "$cmd" "$exit_code" "$NEGATIVE"
        cmd_result=$?
        
        if [[ "$DEBUG" == "true" ]]; then
            echo -e "${BLUE}[DEBUG]${NC} evaluate_command_result returned: $cmd_result"
        fi
        
        COMMAND_EVAL_RESULTS+=("$cmd_result")
        
        # Update overall result (fail if any command fails)
        if [ $cmd_result -ne 0 ]; then
            OVERALL_RESULT=1
        fi
        
        COMMAND_COUNT=$((COMMAND_COUNT + 1))
    fi
done < <(echo "$COMMANDS_JSON" | jq -r '.[]')

# Report final result
if [ $OVERALL_RESULT -eq 0 ]; then
    echo -e "${GREEN}[PASS]${NC} $RULE_ID: $RULE_TITLE"
else
    echo -e "${RED}[FAIL]${NC} $RULE_ID: $RULE_TITLE"
fi

# Display command details
echo -e "\n${YELLOW}[COMMAND DETAILS]${NC}"
echo "Command count: $COMMAND_COUNT"
if [ $COMMAND_COUNT -gt 0 ]; then
    for i in $(seq 0 $((COMMAND_COUNT - 1))); do
        echo "Command $i: ${COMMAND_RESULTS[$i]}"
        echo "  Exit code: ${COMMAND_EXIT_CODES[$i]}"
        echo "  Evaluated result: ${COMMAND_EVAL_RESULTS[$i]}"
        echo "  Output: ${COMMAND_OUTPUTS[$i]}"
    done
else
    echo "  No commands were executed or tracked."
fi

# Debug output
if [[ "$DEBUG" == "true" ]]; then
    echo -e "${BLUE}[DEBUG]${NC} Rule ID: $RULE_ID"
    echo -e "${BLUE}[DEBUG]${NC} Rule Title: $RULE_TITLE"
    echo -e "${BLUE}[DEBUG]${NC} Check Content: $CHECK_CONTENT"
    echo -e "${BLUE}[DEBUG]${NC} Commands: $COMMANDS_JSON"
    echo -e "${BLUE}[DEBUG]${NC} Negative Requirement: $NEGATIVE"
    echo -e "${BLUE}[DEBUG]${NC} Overall Result: $OVERALL_RESULT"
fi

# Clean up
if [ -d "$CMD_DIR" ]; then
    rm -rf "$CMD_DIR"
fi

echo -e "${BLUE}[INFO]${NC} Check completed."

# Return exit code based on compliance
if [ $OVERALL_RESULT -eq 0 ]; then
    exit 0
else
    exit 1
fi
