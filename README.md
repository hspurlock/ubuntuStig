# Ubuntu STIG Compliance Checker

A comprehensive tool for checking Ubuntu systems against Security Technical Implementation Guide (STIG) compliance requirements. This tool automates the verification of security controls and configurations required by the Defense Information Systems Agency (DISA) STIGs for Ubuntu systems.

## Features

- Automated checking of hundreds of STIG requirements
- Detailed reporting of compliance status
- Intelligent evaluation of command results
- Special case handling for complex checks
- Color-coded output for easy interpretation
- Summary statistics of compliance status

### Script Generation

The main compliance script is generated using:

```bash
python3 utils/generate_blocks_improved.py <xml_file> [output_file]
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
sudo ./run_scan_with_full_colors.sh <scan_script> <output_file> [--no-color] [--csv]
```

Parameters:
- `<scan_script>`: Path to the STIG compliance script (e.g., `./ubuntu.sh`)
- `<output_file>`: File where the scan results will be saved
- `--no-color` (optional): Strip color codes from the output file for better readability in text editors
- `--csv` (optional): Generate a CSV report in addition to the text output for easier data analysis and reporting

Examples:
```bash
# For Ubuntu 22.04
sudo ./run_scan_with_full_colors.sh ./ubuntu_22-04_v2r2.sh ubuntu22_results.txt

# For Ubuntu 24.04
sudo ./run_scan_with_full_colors.sh ./ubuntu_24-04_v1r1.sh ubuntu24_results.txt

# Generate both text and CSV reports
sudo ./run_scan_with_full_colors.sh ./ubuntu_24-04_v1r1.sh ubuntu24_results.txt --csv
```

## Running Against Docker Containers

You can run the STIG compliance checks against a running Docker container using the following approach:

```bash
# Copy the appropriate script to the container (example for Ubuntu 22.04)
docker cp ubuntu_22-04_v2r2.sh <container_id>:/tmp/

# Execute the script inside the container
docker exec -it <container_id> bash -c "cd /tmp && chmod +x ubuntu_22-04_v2r2.sh && ./ubuntu_22-04_v2r2.sh"
```

For a more comprehensive assessment with saved results:

```bash
# Copy the necessary scripts to the container (choose the appropriate Ubuntu version)
docker cp ubuntu_22-04_v2r2.sh <container_id>:/tmp/
docker cp run_scan_with_full_colors.sh <container_id>:/tmp/

# Execute inside the container
docker exec -it <container_id> bash -c "cd /tmp && chmod +x *.sh && ./run_scan_with_full_colors.sh ./ubuntu_22-04_v2r2.sh /tmp/stig_results.txt --csv"

# Retrieve the results (both text and CSV)
docker cp <container_id>:/tmp/stig_results.txt ./container_stig_results.txt
docker cp <container_id>:/tmp/stig_results.csv ./container_stig_results.csv
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

## Requirements

- Ubuntu 24.04 LTS
- Bash shell
- Root privileges for running the script
