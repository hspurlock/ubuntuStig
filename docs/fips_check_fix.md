# FIPS Mode Check Fix

## Problem

The STIG compliance script was incorrectly handling the FIPS mode check (SV-270744r1066721_rule). When the `/proc/sys/crypto/fips_enabled` file doesn't exist, the script was returning "NOT_CHECKED" instead of "FAIL", which is incorrect according to the STIG requirements.

The check should fail if:
1. The file `/proc/sys/crypto/fips_enabled` doesn't exist, or
2. The file exists but doesn't contain the value "1"

## Solution

Added special case handling in the `evaluate_command_result` function for the FIPS mode check that:

1. Detects when the file is missing based on the error message
2. Returns "FAIL" with a clear error message explaining that FIPS mode is not enabled
3. Provides different error messages depending on whether the file is missing or just doesn't contain the value "1"

The implementation checks for:
- The specific command pattern `grep -i 1 /proc/sys/crypto/fips_enabled`
- The rule ID pattern `SV-270744`
- The error message `No such file or directory` to detect when the file is missing

## Benefits

This fix ensures that systems correctly identify when FIPS mode is not enabled, rather than reporting an inconclusive "NOT_CHECKED" status, improving the accuracy of the STIG compliance assessment.

## Testing

A test script (`tests/test_fips_check.sh`) has been created to verify the fix works correctly in all scenarios:
- When the file doesn't exist (should FAIL)
- When the file exists but doesn't contain "1" (should FAIL)
- When the file exists and contains "1" (should PASS)

## Implementation

The fix was implemented in both:
1. The main script (`ubuntu.sh`)
2. The script generator (`utils/generate_blocks_improved.py`) to ensure future generated scripts include this fix
