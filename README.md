# STIG Compliance Checker

This tool generates and runs automated compliance checks for Ubuntu STIG requirements based on XCCDF files.

## Requirements

- Python 3.6+
- Root access (sudo) for running compliance checks
- Required Python packages (install via `pip install -r requirements.txt`):
  - lxml
  - xmltodict

## Available Scripts

Two versions of the checker are provided:

1. `stig_checker_html.py`: Generates an HTML report with a modern, interactive interface
2. `stig_checker_json.py`: Generates a JSON report for programmatic processing

## Usage

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Generate compliance check script (choose one):
```bash
# For HTML report
python stig_checker_html.py path/to/xccdf.xml

# For JSON report
python stig_checker_json.py path/to/xccdf.xml
```

This will create a bash script named after your input file (e.g., `U_CAN_Ubuntu_24-04_LTS_STIG_V1R1_Manual-xccdf_stig_check.sh`) that performs the compliance checks.

3. Run the compliance checks (requires root privileges):
```bash
sudo ./[generated-script-name].sh
```

## Features

- Automatic script naming based on input XCCDF file
- Real-time check execution with color-coded output:
  - 🟢 Green: PASS
  - 🔴 Red: FAIL
  - 🟡 Yellow: MANUAL CHECK NEEDED
- Graceful handling of interrupted checks (Ctrl+C)
- Detailed JSON report generation
- Command timeout handling (5s per command)
- Automatic detection of commands requiring manual verification

## Output

The script provides:
1. Real-time results with color-coded status for each check in the terminal
2. A comprehensive HTML report in `stig_results/report.html` featuring:
   - Summary statistics with color-coded status indicators
   - Detailed results table with rule IDs, titles, and status badges
   - Modern, responsive design for easy reading
   - Timestamp of report generation

## Report Formats

### HTML Report (`stig_checker_html.py`)

Provides a comprehensive, visually appealing report with:

1. Summary Section
   - Total rules checked
   - Number of passed checks (green)
   - Number of failed checks (red)
   - Number of manual checks needed (yellow)

2. Detailed Results Table
   - Rule ID and Title
   - Status Badge (color-coded)
     - PASS: Green badge
     - FAIL: Red badge
     - MANUAL: Yellow badge

3. Visual Features
   - Modern, responsive design
   - Color-coded status indicators
   - Interactive table with hover effects
   - Proper text wrapping for readability
   - Report generation timestamp

### JSON Report (`stig_checker_json.py`)

Provides a structured data format ideal for:
- Programmatic analysis
- Integration with other tools
- Custom report generation
- Data processing and analytics

JSON Structure:
```json
{
  "RULE-ID": {
    "status": "pass|fail|manual",
    "title": "Rule Title"
  }
}
```

## Core Features

### Execution
- Parses XCCDF files to extract STIG requirements
- Automatic script naming based on input file
- Supports both HTML and JSON report formats
- Real-time execution feedback in terminal
- Color-coded terminal output:
  - 🟢 Green: PASS
  - 🔴 Red: FAIL
  - 🟡 Yellow: MANUAL CHECK NEEDED
- Command timeout handling (5s per command)
- Graceful interruption handling (Ctrl+C)

### Security
- Root privilege enforcement for system checks
- Secure file permissions:
  - Results directory: 755
  - Report files: 644
- Safe command execution practices
- Automatic sudo removal (runs as root)

## Error Handling

### Command Execution
- Timeout after 5 seconds for hanging commands
- Automatic manual flag for commands with placeholders
- Graceful handling of command failures

### Input Validation
- Validates XCCDF file format
- Checks for root privileges
- Verifies file permissions

### Runtime Protection
- Handles script interruption (Ctrl+C)
- Generates partial reports if interrupted
- Maintains consistent file permissions
- Cleans up temporary files

## Best Practices

1. Always run compliance checks with root privileges
2. Review manual check requirements thoroughly
3. Keep XCCDF files up to date
4. Store reports securely
5. Use HTML reports for human review
6. Use JSON reports for automation

