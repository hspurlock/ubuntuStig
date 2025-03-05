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
sudo ./run_scan_with_full_colors.sh <scan_script> <output_file> [--no-color]
```

Parameters:
- `<scan_script>`: Path to the STIG compliance script (e.g., `./ubuntu.sh`)
- `<output_file>`: File where the scan results will be saved
- `--no-color` (optional): Strip color codes from the output file for better readability in text editors

Examples:
```bash
# For Ubuntu 22.04
sudo ./run_scan_with_full_colors.sh ./ubuntu_22-04_v2r2.sh ubuntu22_results.txt

# For Ubuntu 24.04
sudo ./run_scan_with_full_colors.sh ./ubuntu_24-04_v1r1.sh ubuntu24_results.txt
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
docker exec -it <container_id> bash -c "cd /tmp && chmod +x *.sh && ./run_scan_with_full_colors.sh ./ubuntu_22-04_v2r2.sh /tmp/stig_results.txt"

# Retrieve the results
docker cp <container_id>:/tmp/stig_results.txt ./container_stig_results.txt
```

For CSV output as well, use the `ubuntu_22-04_v2r2_csv.sh` script in lieu of `ubuntu_22-04_v2r2.sh`. Output is in the container `output.csv`.

Example first several lines of `output.csv`:

```text
"Rule ID", "Status", "Comments", "Finding Details"
"SV-260470r958472_rule", "Not Reviewed", "grep -i password /boot/grub/grub.cfg", "grep: /boot/grub/grub.cfg: No such file or directory"
"SV-260471r991555_rule", "Not Reviewed", "grep \"^\s*linux\" /boot/grub/grub.cfg", "grep: /boot/grub/grub.cfg: No such file or directory"
"SV-260472r958524_rule", "Open", "grep -ir kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null", "/etc/sysctl.d/10-kernel-hardening.conf:# kernel.dmesg_restrict = 0"
"SV-260473r958550_rule", "Open", "systemctl status kdump.service", "./ubuntu_22-04_v2r2_csv.sh: line 945: systemctl: command not found"
```

## Requirements

- Ubuntu 24.04 LTS
- Bash shell
- Root privileges for running the script
