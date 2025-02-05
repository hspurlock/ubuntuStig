# Ubuntu 22.04 STIG Compliance Scanner

This tool performs automated STIG (Security Technical Implementation Guide) compliance scanning for Ubuntu 22.04 systems using OpenSCAP. It can be run directly on the host system or within a Docker container.

## Features

- Automated STIG compliance scanning using OpenSCAP
- Support for any Ubuntu 22.04 STIG benchmark zip file
- Detailed HTML and XML reports
- Compliance statistics and analysis
- Docker container support
- Profile-based scanning

## Prerequisites

- Ubuntu 22.04 LTS (for direct installation)
- Python 3.10 or higher (for direct installation)
- Docker (for container-based execution)
- STIG benchmark file for Ubuntu 22.04

## Docker Execution (Recommended)

1. Clone this repository:
```bash
git clone https://github.com/hspurlock/ubuntuStig.git
cd ubuntuStig
```

2. Download the STIG benchmark:
```bash
wget https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_22-04_LTS_V2R2_STIG.zip
```

3. Build the Docker image:
```bash
docker build -t ubuntu-stig-scanner .
```

4. Run the scanner:
```bash
docker run --privileged -v $(pwd)/reports:/app/reports ubuntu-stig-scanner
```

Additional Docker options:
- Specify a different STIG profile:
```bash
docker run --privileged -v $(pwd)/reports:/app/reports ubuntu-stig-scanner python3 stig_scanner.py --profile MAC-1_Classified
```

- Available profiles:
  - MAC-1_Public (default)
  - MAC-1_Classified
  - MAC-1_Sensitive
  - MAC-2_Public
  - MAC-2_Classified
  - MAC-2_Sensitive
  - MAC-3_Public
  - MAC-3_Classified
  - MAC-3_Sensitive

- Mount a custom STIG zip file:
```bash
docker run --privileged \
  -v $(pwd)/reports:/app/reports \
  -v /path/to/custom/stig.zip:/app/stig_files/stig.zip \
  ubuntu-stig-scanner
```

## Direct Installation

1. Clone this repository:
```bash
git clone https://github.com/hspurlock/ubuntuStig.git
cd ubuntuStig
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Install system dependencies:
```bash
sudo apt-get update
sudo apt-get install -y libopenscap8 openscap-scanner ssg-base ssg-debderived
```

4. Download STIG benchmark:
```bash
wget https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_22-04_LTS_V2R2_STIG.zip -O U_CAN_Ubuntu_22-04_LTS_V2R2_STIG.zip
```

5. Run the scanner:
```bash
python3 stig_scanner.py
```

## Reports

Reports are stored in the `reports` directory:
- HTML reports: Human-readable detailed findings
- XML reports: Machine-readable raw scan data

Each scan generates:
- A timestamped HTML report with detailed findings
- A timestamped XML report with raw data
- A compliance summary showing:
  - Total number of rules checked
  - Number of passed rules
  - Number of failed rules
  - Overall compliance rate

## Troubleshooting

1. Docker permission issues:
   - Ensure the reports directory has proper permissions
   - The Docker container runs as a non-root user for security

2. STIG file issues:
   - Verify the STIG zip file is for Ubuntu 22.04
   - Check that the zip file contains the XCCDF benchmark XML

3. OpenSCAP errors:
   - The --privileged flag is required for system checks
   - Some checks may be skipped if they require additional system access

## Security Considerations

- This tool requires sudo privileges to perform system scans
- Reports may contain sensitive system information
- Ensure proper access controls are in place for the reports directory
- The systemd service runs as root to perform system-level scans
- Docker socket access is required for container scanning
