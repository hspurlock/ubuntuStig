# STIG Compliance Checker

This tool generates and runs automated compliance checks for Ubuntu STIG requirements based on XCCDF files.

## Requirements

- Python 3.6+
- Root access (sudo) for running compliance checks
- Required Python packages (install via `pip install -r requirements.txt`):
  - lxml
  - xmltodict

## Available Scripts

The checker is provided as:

1. `stig_checker_html.py`: The main script that generates an HTML report with a modern, interactive interface

## Usage

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. For HTML Report Generation:
```bash
python stig_checker_html.py path/to/xccdf.xml
```

3. Run the compliance checks (requires root privileges):
```bash
sudo ./[generated-script-name].sh
```

## Features

- Automatic script naming based on input XCCDF file
- Real-time check execution with color-coded output:
  - Green: PASS
  - Red: FAIL
  - Yellow: MANUAL CHECK NEEDED
- Graceful handling of interrupted checks (Ctrl+C)
- Detailed report generation
- Command timeout handling (5s per command)
- Automatic detection of commands requiring manual verification

## Supported XCCDF Files

The tool has been tested with the following XCCDF files:
- `U_CAN_Ubuntu_24-04_LTS_STIG_V1R1_Manual-xccdf.xml`: Ubuntu 24.04 LTS STIG (Version 1 Release 1)
- `U_CAN_Ubuntu_22-04_LTS_STIG_V2R2_Manual-xccdf.xml`: Ubuntu 22.04 LTS STIG (Version 2 Release 2)

## Output

The script provides:
1. Real-time results with color-coded status for each check in the terminal
2. A comprehensive HTML report in `stig_results/report.html` featuring:
   - Summary statistics with color-coded status indicators
   - Detailed results table with rule IDs, titles, and status badges
   - Modern, responsive design for easy reading
   - Timestamp of report generation

## Report Format

### HTML Report

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

## Core Features

### Execution
- Parses XCCDF files to extract STIG requirements
- Automatic script naming based on input file
- HTML report format
- Real-time execution feedback in terminal
- Color-coded terminal output:
  - Green: PASS
  - Red: FAIL
  - Yellow: MANUAL CHECK NEEDED
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

## Docker Container Scanning

You can use this tool to scan Docker containers for STIG compliance. Since containers often have a reduced subset of the full OS, some checks may fail or not be applicable. However, this approach still provides valuable security insights.

### Scanning Docker Containers

1. Generate the compliance check script:
```bash
python stig_checker_html.py -x path/to/xccdf.xml -o container_scan.sh
```

2. Run the script inside a Docker container:
```bash
# Method 1: Copy and execute the script
docker cp container_scan.sh container_name:/tmp/
docker exec -it container_name bash -c "chmod +x /tmp/container_scan.sh && /tmp/container_scan.sh"

# Method 2: Direct execution (no file copy needed)
cat container_scan.sh | docker exec -i container_name bash
```

### Container-Specific Considerations

- **Reduced Environment**: Containers typically have a minimal OS installation
- **Privileged Mode**: Some checks may require running the container in privileged mode
- **Missing Tools**: Standard diagnostic tools may be absent in minimal container images
- **Post-processing**: Consider filtering results to focus on container-relevant security controls

### Handling Container-Specific Failures

For optimal container security assessment:

1. Focus on container-relevant checks:
   - File permissions
   - Package versions
   - Network settings
   - User privileges

2. Consider supplementing with container-specific security tools:
   - Docker Bench for Security
   - Clair
   - Trivy

## Future Development

- Support for additional Linux distributions
- Integration with CI/CD pipelines
- Export formats for security information management systems
- Automatic remediation suggestions
- Customizable check profiles
