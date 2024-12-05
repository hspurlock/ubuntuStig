#!/usr/bin/env python3

import subprocess
import os
import datetime
import schedule
import time
import json
import pandas as pd
import matplotlib.pyplot as plt
# Removed Docker import
from pathlib import Path
from jinja2 import Template

class STIGScanner:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.reports_dir = self.base_dir / 'reports'
        self.reports_dir.mkdir(exist_ok=True)
        # Removed Docker client initialization
        
        # Ensure OpenSCAP is installed
        self._check_dependencies()

    def _check_dependencies(self):
        """Check if required system dependencies are installed."""
        try:
            subprocess.run(['oscap', '--version'], check=True, capture_output=True)
            # Check Docker availability
            # Removed Docker scanning
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("OpenSCAP not found. Installing required packages...")
            subprocess.run(['sudo', 'apt-get', 'update'], check=True)
            subprocess.run(['sudo', 'apt-get', 'install', '-y', 'libopenscap8', 'openscap-scanner', 'ssg-base', 'ssg-debderived'], check=True)
        
        # Removed Docker scanning

    def download_stig_benchmark(self):
        """Load the DISA STIG for Ubuntu 22.04 from a local zip file."""
        benchmark_dir = self.base_dir / 'benchmarks'
        benchmark_dir.mkdir(exist_ok=True)

        # Load benchmark from local zip file
        local_zip_path = self.base_dir / 'U_CAN_Ubuntu_22-04_LTS_V2R2_STIG.zip'
        subprocess.run(['unzip', '-o', str(local_zip_path), '-d', str(benchmark_dir)], check=True)

    def run_scan(self):
        """Execute STIG compliance scan."""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = self.reports_dir / f'stig_report_{timestamp}'
        
        # Path to the STIG benchmark XML file
        benchmark_path = self.base_dir / 'benchmarks' / 'U_CAN_Ubuntu_22-04_LTS_V2R2_Manual_STIG' / 'U_CAN_Ubuntu_22-04_LTS_STIG_V2R2_Manual-xccdf.xml'
        
        try:
            # Run OpenSCAP scan
            subprocess.run([
                'oscap', 'xccdf', 'eval',
                '--profile', 'xccdf_mil.disa.stig_profile_MAC-1_Classified',
                '--results', f'{str(report_path)}.xml',
                '--report', f'{str(report_path)}.html',
                str(benchmark_path)
            ], check=True)
            
            print(f"Scan completed successfully. Reports saved to {report_path}.xml and {report_path}.html")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error during scan: {e}")
            return False

def main():
    scanner = STIGScanner()
    
    # Run scan immediately
    print("Running STIG compliance scan...")
    scanner.download_stig_benchmark()
    scanner.run_scan()

if __name__ == "__main__":
    import sys
    import logging

    # Set up logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger()

    try:
        logger.info("Starting Ubuntu STIG Scanner service")
        main()
    except KeyboardInterrupt:
        logger.info("Service stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Service error: {str(e)}")
        sys.exit(1)
