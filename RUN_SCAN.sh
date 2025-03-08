#!/bin/bash

# Function to generate CSV report from STIG scan results
generate_csv_report() {
  local input_file="$1"
  local output_csv="$2"
  
  # Check if the input file exists
  if [ ! -f "$input_file" ]; then
    echo "Error: Input file '$input_file' not found."
    return 1
  fi

  # Create CSV header
  echo "Rule ID,Title,Status,Details" > "$output_csv"

  # Process the input file
  # This will extract rule IDs, titles, and results from the STIG scan output
  echo "Processing $input_file..."

  # Strip ANSI color codes for processing
  local tmp_file=$(mktemp)
  sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' "$input_file" > "$tmp_file"

  # Extract and process each rule
  local current_rule=""
  local current_title=""
  local current_status=""
  local current_details=""
  local in_check_content=false
  local check_content=""

  while IFS= read -r line; do
    # Check for rule ID line (both OS and Docker formats)
    if [[ "$line" =~ ^===\ Checking\ (SV-[0-9]+r[0-9]+_rule)\ ===$ ]] || [[ "$line" =~ ^=+\s*Checking\s+(SV-[0-9]+r[0-9]+_rule)\s*=+$ ]]; then
      # If we have a previous rule, write it to CSV
      if [ -n "$current_rule" ]; then
        # Escape double quotes in fields for CSV
        current_title="${current_title//\"/\"\"}"
        current_details="${current_details//\"/\"\"}"
        
        # Write to CSV
        echo "\"$current_rule\",\"$current_title\",\"$current_status\",\"$current_details\"" >> "$output_csv"
      fi
      
      # Start new rule
      current_rule="${BASH_REMATCH[1]}"
      current_title=""
      current_status=""
      current_details=""
      in_check_content=false
      check_content=""
    
    # Check for title line
    elif [[ "$line" =~ ^Title:\s+(.+)$ ]] && [ -n "$current_rule" ]; then
      current_title="${BASH_REMATCH[1]}"
    
    # Check for result line (both OS and Docker formats)
    elif [[ "$line" =~ ^\[(PASS|FAIL|MANUAL|NOT_CHECKED|NOT_APPLICABLE)\]\ (SV-[0-9]+r[0-9]+_rule):\ (.+)$ ]]; then
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
    
    # Collect command outputs and error messages for details (OS format)
    elif [[ "$line" =~ ^Command\ [0-9]+\ Result:\ (PASS|FAIL|MANUAL|NOT_CHECKED)$ ]]; then
      cmd_result="${BASH_REMATCH[1]}"
      if [ "$cmd_result" != "PASS" ]; then
        if [ -n "$current_details" ]; then
          current_details="$current_details; "
        fi
        current_details="${current_details}Command result: $cmd_result"
      fi
    
    # Capture error messages and command outputs (they typically appear after a command result)
    elif [[ "$line" =~ ^(Error|Warning|Output|Exit\ Code):\ .*$ ]] && [ -n "$current_rule" ]; then
      if [ -n "$current_details" ]; then
        current_details="$current_details; "
      fi
      current_details="${current_details}$line"
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
    
  done < "$tmp_file"

  # Write the last rule if there is one
  if [ -n "$current_rule" ]; then
    # Escape double quotes in fields for CSV
    current_title="${current_title//\"/\"\"}"
    current_details="${current_details//\"/\"\"}"
    
    # Write to CSV
    echo "\"$current_rule\",\"$current_title\",\"$current_status\",\"$current_details\"" >> "$output_csv"
  fi

  # Clean up
  rm "$tmp_file"
  
  return 0
}

# Check if required parameters are provided
if [ $# -lt 2 ]; then
  echo "Usage: $0 <scan_script> <output_file> [--no-color] [--csv]"
  echo "Example: $0 ./ubuntu_scan.sh scan_results.txt"
  echo "Options:"
  echo "  --no-color   Strip color codes from the output file"
  echo "  --csv        Generate a CSV report in addition to the text output"
  exit 1
fi

SCAN_SCRIPT="$1"
OUTPUT_FILE="$2"
STRIP_COLORS=false
GENERATE_CSV=false

# Check for optional flags
shift 2
while [ $# -gt 0 ]; do
  case "$1" in
    --no-color)
      STRIP_COLORS=true
      ;;
    --csv)
      GENERATE_CSV=true
      ;;
    *)
      echo "Unknown option: $1"
      echo "Valid options: --no-color, --csv"
      exit 1
      ;;
  esac
  shift
done

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

# Generate CSV report if requested
if [ "$GENERATE_CSV" = true ]; then
  CSV_OUTPUT="${OUTPUT_FILE%.*}.csv"
  
  echo "Generating CSV report..."
  generate_csv_report "$OUTPUT_FILE" "$CSV_OUTPUT"
  if [ $? -eq 0 ]; then
    echo "CSV report saved to: $CSV_OUTPUT"
  else
    echo "Error: Failed to generate CSV report."
  fi
fi

# Clean up the temporary file
rm "$TMP_OUTPUT"
