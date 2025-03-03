#!/bin/bash

# Check if required parameters are provided
if [ $# -lt 2 ]; then
  echo "Usage: $0 <scan_script> <output_file> [--no-color]"
  echo "Example: $0 ./ubuntu_scan.sh scan_results.txt"
  echo "Add --no-color as third parameter to strip color codes from the output file"
  exit 1
fi

SCAN_SCRIPT="$1"
OUTPUT_FILE="$2"
STRIP_COLORS=false

# Check if the --no-color flag is provided
if [ $# -ge 3 ] && [ "$3" == "--no-color" ]; then
  STRIP_COLORS=true
fi

# Check if the scan script exists and is executable
if [ ! -f "$SCAN_SCRIPT" ]; then
  echo "Error: Scan script '$SCAN_SCRIPT' not found."
  exit 1
fi

if [ ! -x "$SCAN_SCRIPT" ]; then
  echo "Error: Scan script '$SCAN_SCRIPT' is not executable."
  echo "Run 'chmod +x $SCAN_SCRIPT' to make it executable."
  exit 1
fi

# Force color output even when redirecting
export TERM=xterm-256color
export FORCE_COLOR=true

# Explicitly tell commands to use colors even when output is not a terminal
export CLICOLOR_FORCE=1

# Make sure the script knows we want colors
echo "Running STIG scan script: $SCAN_SCRIPT"
echo "Results will be saved to: $OUTPUT_FILE"

# Create a temporary file for the raw output
TMP_OUTPUT=$(mktemp)

# Run the scan with unbuffered output and capture to both terminal and temp file
stdbuf -oL -eL "$SCAN_SCRIPT" 2>&1 | tee "$TMP_OUTPUT"

# Process the output based on whether we want to strip colors
if [ "$STRIP_COLORS" = true ]; then
  # Strip ANSI color codes for a clean text file
  sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' "$TMP_OUTPUT" > "$OUTPUT_FILE"
  echo ""
  echo "Scan completed. Results saved to $OUTPUT_FILE (colors stripped)"
  echo ""
  echo "The output file contains plain text without color codes."
  echo "You can view it with any text viewer:"
  echo "less $OUTPUT_FILE"
  echo "cat $OUTPUT_FILE"
else
  # Keep the colors for viewing with color-aware tools
  cp "$TMP_OUTPUT" "$OUTPUT_FILE"
  echo ""
  echo "Scan completed. Results saved to $OUTPUT_FILE (with color codes)"
  echo ""
  echo "To view the results with colors preserved, use:"
  echo "less -R $OUTPUT_FILE"
  
  # Also create a plain text version
  PLAIN_OUTPUT="${OUTPUT_FILE%.*}_plain.txt"
  sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' "$TMP_OUTPUT" > "$PLAIN_OUTPUT"
  echo ""
  echo "A plain text version (without colors) is also available at:"
  echo "$PLAIN_OUTPUT"
fi

# Clean up the temporary file
rm "$TMP_OUTPUT"
