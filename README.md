# Ubuntu 22.04 STIG Compliance Scanner

This tool performs automated STIG (Security Technical Implementation Guide) compliance scanning for Ubuntu 22.04 systems and generates monthly reports.

## Features

- Automated STIG compliance scanning using OpenSCAP
- Monthly scheduled scans
- Detailed HTML reports for each scan
- Monthly trend analysis and visualization
- Docker container security scanning
- Systemd service integration
- Automatic dependency management

## Prerequisites

- Ubuntu 22.04 LTS
- Python 3.8 or higher
- sudo privileges (for system scanning)
- Docker (optional, for container scanning)

## Installation

1. Clone this repository:
```bash
git clone [repository-url]
cd ubuntu-stig-scanner
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Install system dependencies (will be done automatically on first run):
```bash
sudo apt-get update
sudo apt-get install -y libopenscap8 openscap-scanner ssg-base ssg-debderived
```

## Running as a Systemd Service

1. Copy the service file to systemd directory:
```bash
sudo cp ubuntu-stig-scanner.service /etc/systemd/system/
```

2. Reload systemd daemon:
```bash
sudo systemctl daemon-reload
```

3. Enable and start the service:
```bash
sudo systemctl enable ubuntu-stig-scanner
sudo systemctl start ubuntu-stig-scanner
```

4. Check service status:
```bash
sudo systemctl status ubuntu-stig-scanner
```

Service logs can be viewed using:
```bash
sudo journalctl -u ubuntu-stig-scanner
```

## Manual Usage

You can also run the scanner manually without systemd:
```bash
python3 stig_scanner.py
```

The script will:
- Download the latest DISA STIG benchmark
- Perform an initial scan
- Generate a baseline report
- Schedule monthly scans

## Reports

Reports are stored in the `reports` directory:
- HTML reports: Detailed findings for each scan
- XML reports: Raw scan data
- Monthly trend analysis graphs
- Docker container security reports (JSON format)

## Scheduling

The service performs the following scheduled tasks:
- STIG compliance scan: Monthly at 00:00
- Monthly report generation: Monthly at 01:00
- Docker container security scan: Daily at 02:00

## Security Considerations

- This tool requires sudo privileges to perform system scans
- Reports may contain sensitive system information
- Ensure proper access controls are in place for the reports directory
- The systemd service runs as root to perform system-level scans
- Docker socket access is required for container scanning
