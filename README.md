# Ubuntu STIG Compliance Checker

A comprehensive tool for checking Ubuntu systems against Security Technical Implementation Guide (STIG) compliance requirements. This tool automates the verification of security controls and configurations required by the Defense Information Systems Agency (DISA) STIGs for Ubuntu systems.

## Features

- Automated checking of hundreds of STIG requirements
- Detailed reporting of compliance status
- Intelligent evaluation of command results
- Special case handling for complex checks including:
  - Sysctl configuration checks
  - X11Forwarding SSH configuration checks
  - FIPS mode validation
  - Regex pattern handling for grep commands
- Color-coded output for easy interpretation
- Summary statistics of compliance status

### Script Generation

The main compliance script is generated using:

```bash
python3 utils/generate_OS_stig_script.py <xml_file> [output_file]
```

## Usage

For Ubuntu 22.04 LTS:
```bash
sudo ./ubuntu_22-04_v2r2.sh
```

For Ubuntu 24.04 LTS:
```bash
sudo ./ubuntu_24-04_v1r1.sh
```

For a more colorful output with the ability to save results to a file:
```bash
sudo ./RUN_SCAN.sh <scan_script> <output_file> [--no-color] [--csv]
```

Parameters:
- `<scan_script>`: Path to the STIG compliance script (e.g., `./ubuntu.sh`)
- `<output_file>`: File where the scan results will be saved
- `--no-color` (optional): Strip color codes from the output file for better readability in text editors
- `--csv` (optional): Generate a CSV report in addition to the text output for easier data analysis and reporting. The CSV file will be created with the same name as the output file but with a `.csv` extension.

Examples:
```bash
# For Ubuntu 22.04
sudo ./RUN_SCAN.sh ./ubuntu_22-04_v2r2.sh ubuntu22_results.txt

# For Ubuntu 24.04
sudo ./RUN_SCAN.sh ./ubuntu_24-04_v1r1.sh ubuntu24_results.txt

# Generate both text and CSV reports
sudo ./RUN_SCAN.sh ./ubuntu_24-04_v1r1.sh ubuntu24_results.txt --csv
```

## CSV Report Generation

The scanning tool now includes integrated CSV report generation functionality. When the `--csv` option is specified, the script will automatically process the scan results and generate a CSV report with the following information:

- Rule ID: The unique identifier for each STIG rule
- Title: The descriptive title of the rule
- Status: The compliance status (PASS, FAIL, NOT_CHECKED, etc.)
- Details: Additional information about the check, including command outputs and error messages

The CSV report is saved to a file with the same name as the output file but with a `.csv` extension, making it easy to import into spreadsheet applications or data analysis tools.

## Container STIG Compatibility

The repository includes a specialized Container STIG compatibility feature that generates compliance scripts tailored specifically for container environments. This feature filters out checks that are not applicable to containers and adapts relevant checks to work properly in containerized environments.

### Generating Container-Compatible STIG Scripts

```bash
python3 utils/generate_Container_stig_script.py <xml_file> <output_script_file>
```

Example:
```bash
python3 utils/generate_Container_stig_script.py U_CAN_Ubuntu_24-04_LTS_STIG_V1R1_Manual-xccdf.xml container_ubuntu_24-04_v1r1.sh
```

### Key Features

- **Intelligent Filtering**: Excludes checks not applicable to containers (systemd, boot, kernel parameters, etc.)
- **Conditional SSH Checks**: Only evaluates SSH banner requirements if SSH is installed
- **Comprehensive Exclusions**: Removes checks related to AppArmor, PAM, sudo, chrony, PIV credentials, and session locking
- **Improved Compliance Scores**: Provides more accurate assessment of container security posture

For more details, see [docs/container_stig_feature.md](docs/container_stig_feature.md).

### Running Container-Compatible STIG Checks

You can run the Container-compatible STIG compliance checks against a running Docker container:

```bash
# Copy the Container-compatible script to the container
docker cp container_ubuntu_24-04_v1r1.sh <container_id>:/

# Execute the script inside the container
docker exec <container_id> /container_ubuntu_24-04_v1r1.sh
```

For a more comprehensive assessment with saved results:

```bash
# Copy the necessary scripts to the container
docker cp container_ubuntu_24-04_v1r1.sh <container_id>:/tmp/
docker cp RUN_SCAN.sh <container_id>:/tmp/

# Execute inside the container
docker exec -it <container_id> bash -c "cd /tmp && chmod +x *.sh && ./RUN_SCAN.sh ./container_ubuntu_24-04_v1r1.sh /tmp/container_stig_results.txt --csv"

# Retrieve the results (both text and CSV)
docker cp <container_id>:/tmp/container_stig_results.txt ./container_stig_results.txt
docker cp <container_id>:/tmp/container_stig_results.csv ./container_stig_results.csv
```

## CSV Reports

The `--csv` option generates a structured report in CSV format, making it easier to:

- Import results into spreadsheet applications for analysis
- Generate custom reports and visualizations
- Track compliance over time
- Share results with stakeholders in a standard format

The CSV file contains the following columns:

1. **Rule ID** - The STIG rule identifier (e.g., SV-270657r1066460_rule)
2. **Title** - The title of the STIG rule
3. **Status** - The compliance status (PASS, FAIL, MANUAL, or NOT_CHECKED)
4. **Details** - Additional information about failures or issues

For more information about the CSV report feature, see [docs/csv_report_feature.md](docs/csv_report_feature.md).

## Special Case Handling

The STIG compliance script includes specialized handling for complex checks:

### Sysctl Configuration Checks

The script intelligently evaluates sysctl configuration settings by:
- Extracting the sysctl parameter name from the command
- Checking for uncommented settings with values 1 or 0
- Handling commented settings appropriately
- Providing detailed error messages for different failure cases

For more details, see [docs/sysctl_check_improvements.md](docs/sysctl_check_improvements.md).

### X11Forwarding SSH Configuration Checks

Special handling for SSH X11Forwarding checks ensures:
- Proper command syntax execution
- Verification of uncommented X11Forwarding settings
- Correct evaluation of secure ("no") vs. insecure ("yes") settings
- Detailed error messages for different configuration states

For more details, see [docs/x11forwarding_check_fix.md](docs/x11forwarding_check_fix.md).

### FIPS Mode Validation

The script properly validates FIPS mode by:
- Correctly identifying when /proc/sys/crypto/fips_enabled doesn't exist
- Returning appropriate FAIL status instead of NOT_CHECKED
- Providing clear error messages explaining FIPS mode status

This ensures accurate compliance assessment for systems requiring FIPS compliance.


### Improved Command Evaluation

The script now features an enhanced command evaluation system that:
- Intelligently evaluates command results based on command type and output
- Properly handles grep commands with exit codes 0 (matches found), 1 (no matches), and 2 (errors)
- Examines actual command output rather than relying solely on exit codes
- Reduces false positives and negatives in compliance checks

## Requirements

- Ubuntu 24.04 LTS
- Bash shell
- Root privileges for running the script

## Testing

The repository includes a comprehensive test suite to validate the functionality of the STIG compliance scripts. The test suite covers OS scanning, Docker scanning, and CSV output functionality.

### Running Tests

To run all tests:

```bash
./test/run_all_tests.sh
```

To run individual test components:

```bash
# Test OS Scanner functionality
./test/test_os_scanner.sh

# Test Container Scanner functionality
./test/test_container_scanner.sh

# Test CSV Output functionality
./test/test_csv_output.sh
```

### Test Components

1. **OS Scanner Tests** (`test_os_scanner.sh`):
   - Basic scan with Ubuntu 22.04 LTS script
   - Basic scan with Ubuntu 24.04 LTS script
   - Scan with specific rule filter
   - Scan with verbose output
   - Scan with HTML output

2. **Docker Scanner Tests** (`test_docker_scanner.sh`):
   - Basic scan with Docker Ubuntu 22.04 LTS script
   - Basic scan with Docker Ubuntu 24.04 LTS script
   - Scan with HTML output

3. **CSV Output Tests** (`test_csv_output.sh`):
   - OS scan with CSV output (Ubuntu 22.04)
   - OS scan with CSV output (Ubuntu 24.04)
   - Docker scan with CSV output
   - CSV output with rule filter

The test suite validates that the scripts generate the expected output files, that these files contain the expected content, and that the CSV reports are properly formatted with the correct headers and data.
