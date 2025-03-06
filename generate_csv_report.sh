#!/bin/bash

# CSV Report Generator for STIG Compliance Results
# This script processes the output of the STIG compliance script and generates a CSV report

# Check if required parameters are provided
if [ $# -lt 2 ]; then
  echo "Usage: $0 <input_file> <output_csv>"
  echo "Example: $0 scan_results.txt scan_results.csv"
  exit 1
fi

INPUT_FILE="$1"
OUTPUT_CSV="$2"

# Check if the input file exists
if [ ! -f "$INPUT_FILE" ]; then
  echo "Error: Input file '$INPUT_FILE' not found."
  exit 1
fi

# Create CSV header
echo "Rule ID,Title,Status,Details" > "$OUTPUT_CSV"

# Process the input file
# This will extract rule IDs, titles, and results from the STIG scan output
echo "Processing $INPUT_FILE..."

# Strip ANSI color codes for processing
TMP_FILE=$(mktemp)
sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' "$INPUT_FILE" > "$TMP_FILE"

# Extract and process each rule
current_rule=""
current_title=""
current_status=""
current_details=""
in_check_content=false
check_content=""

while IFS= read -r line; do
  # Check for rule ID line
  if [[ "$line" =~ ^===\ Checking\ (SV-[0-9]+r[0-9]+_rule)\ ===$ ]]; then
    # If we have a previous rule, write it to CSV
    if [ -n "$current_rule" ]; then
      # Escape double quotes in fields for CSV
      current_title="${current_title//\"/\"\"}"
      current_details="${current_details//\"/\"\"}"
      
      # Write to CSV
      echo "\"$current_rule\",\"$current_title\",\"$current_status\",\"$current_details\"" >> "$OUTPUT_CSV"
    fi
    
    # Start new rule
    current_rule="${BASH_REMATCH[1]}"
    current_title=""
    current_status=""
    current_details=""
    in_check_content=false
    check_content=""
  
  # Check for title line
  elif [[ "$line" =~ ^Title:\ (.+)$ ]] && [ -n "$current_rule" ]; then
    current_title="${BASH_REMATCH[1]}"
  
  # Check for result line
  elif [[ "$line" =~ ^\[(PASS|FAIL|MANUAL|NOT_CHECKED)\]\ (SV-[0-9]+r[0-9]+_rule):\ (.+)$ ]]; then
    # This is a result line, update status
    current_status="${BASH_REMATCH[1]}"
    # Verify rule ID matches
    if [ "${BASH_REMATCH[2]}" != "$current_rule" ]; then
      echo "Warning: Rule ID mismatch: ${BASH_REMATCH[2]} vs $current_rule"
    fi
    # Update title if it was empty
    if [ -z "$current_title" ]; then
      current_title="${BASH_REMATCH[3]}"
    fi
  
  # Collect command outputs and error messages for details
  elif [[ "$line" =~ ^Command\ [0-9]+\ Result:\ (PASS|FAIL|MANUAL|NOT_CHECKED)$ ]]; then
    cmd_result="${BASH_REMATCH[1]}"
    if [ "$cmd_result" != "PASS" ]; then
      if [ -n "$current_details" ]; then
        current_details="$current_details; "
      fi
      current_details="${current_details}Command result: $cmd_result"
    fi
  
  # Capture error messages (they typically appear after a command result)
  elif [[ "$line" =~ ^[A-Za-z].*\ (setting|configuration|file|not\ found|missing|invalid|failed).*$ ]] && [ -n "$current_rule" ]; then
    if [ -n "$current_details" ]; then
      current_details="$current_details; "
    fi
    current_details="${current_details}$line"
  
  # Track check content sections to help with context
  elif [[ "$line" == "Check Content:" ]]; then
    in_check_content=true
    check_content=""
  elif [ "$in_check_content" = true ] && [[ "$line" == "EOF" ]]; then
    in_check_content=false
  elif [ "$in_check_content" = true ]; then
    check_content="$check_content $line"
  fi
  
done < "$TMP_FILE"

# Write the last rule if there is one
if [ -n "$current_rule" ]; then
  # Escape double quotes in fields for CSV
  current_title="${current_title//\"/\"\"}"
  current_details="${current_details//\"/\"\"}"
  
  # Write to CSV
  echo "\"$current_rule\",\"$current_title\",\"$current_status\",\"$current_details\"" >> "$OUTPUT_CSV"
fi

# Clean up
rm "$TMP_FILE"