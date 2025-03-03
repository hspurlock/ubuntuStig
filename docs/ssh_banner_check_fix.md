# SSH Banner Check Fix

## Problem Description

The STIG compliance script was incorrectly evaluating the SSH banner check (SV-270691r1066562_rule) as PASS when it should have been FAIL. The issue was twofold:

1. The script was not properly checking for commented out Banner lines in `/etc/ssh/sshd_config`
2. The script was not properly verifying the content of the banner file against the required DoD Notice and Consent Banner

## Solution Implemented

### 1. Special Case for SSH Banner Configuration Check

Added special handling in the `evaluate_grep_command` function to properly check for SSH banner configuration:

```bash
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
```

This code specifically:
- Checks if there's a Banner line that is not commented out
- Verifies that the Banner is not set to 'none'
- Extracts the banner file path for further checking

### 2. Special Case for SSH Banner Content Check

Added special handling in the `evaluate_command_result` function to verify the content of the banner file:

```bash
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
```

This code:
- Checks specifically for the `cat /etc/issue.net` command in the SV-270691 rule
- Verifies that the content contains key phrases from the required DoD Notice and Consent Banner
- Returns FAIL if any of the required phrases are missing

### 3. Passing Rule ID to Command Evaluation

Modified the `evaluate_command_result` function to accept the rule ID as a parameter:

```bash
evaluate_command_result() {
    local exit_code="$1"
    local output="$2"
    local requirement_type="$3"
    local command="$4"
    local rule_id="$5"
    
    # ... rest of function ...
}
```

And updated the call to this function to include the rule ID:

```bash
cmd_result_{i}=$(evaluate_command_result "$exit_code_{i}" "$output_{i}" "{requirement_type}" "{cmd_escaped}" "{rule_id}")
```

## Benefits

1. **Accurate Evaluation**: The script now correctly identifies when the SSH banner is not properly configured or does not contain the required content.

2. **Detailed Error Messages**: The script provides specific error messages about what aspect of the SSH banner configuration is incorrect.

3. **Rule-Specific Handling**: By passing the rule ID to the command evaluation function, we can implement rule-specific checks without modifying the overall script structure.

## Testing

The fix has been tested with the SSH banner check (SV-270691r1066562_rule) and correctly identifies:
- When the Banner line is commented out in sshd_config
- When the Banner is set to 'none'
- When the banner file does not contain the required DoD Notice and Consent Banner content

## Future Considerations

1. **Additional Banner Checks**: Similar checks may be needed for other banner requirements in the STIG.

2. **More Robust Content Verification**: The current implementation checks for key phrases, but a more robust solution might use a checksum or exact string comparison.

3. **Handling Multiple Banner Files**: The current implementation assumes a single banner file, but some configurations might use multiple files.
