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
    def __init__(self, profile_name=None):
        self.base_dir = Path(__file__).parent
        self.reports_dir = self.base_dir / 'reports'
        self.reports_dir.mkdir(exist_ok=True)
        self.benchmark_dir = self.base_dir / 'benchmarks'
        self.benchmark_dir.mkdir(exist_ok=True)
        self.profile_name = profile_name or 'xccdf_mil.disa.stig_profile_MAC-1_Classified'
        
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

    def find_stig_zip(self):
        """Find any STIG zip file in the base directory or STIG_FILES_DIR."""
        # Check environment variable first
        stig_dir = os.getenv('STIG_FILES_DIR')
        if stig_dir:
            stig_path = Path(stig_dir)
            if stig_path.exists():
                for file in stig_path.glob('*.zip'):
                    if 'STIG' in file.name.upper():
                        return file
        
        # Fallback to base directory
        for file in self.base_dir.glob('*.zip'):
            if 'STIG' in file.name.upper():
                return file
                
        raise FileNotFoundError('No STIG zip file found in STIG_FILES_DIR or base directory')

    def extract_stig_benchmark(self):
        """Extract the STIG benchmark from any available zip file."""
        try:
            # Find and extract the STIG zip file
            zip_file = self.find_stig_zip()
            logging.info(f'Found STIG file: {zip_file.name}')
            
            # Clear existing benchmark directory
            if self.benchmark_dir.exists():
                try:
                    for item in self.benchmark_dir.iterdir():
                        if item.is_dir():
                            for subitem in item.iterdir():
                                subitem.unlink()
                            item.rmdir()
                        else:
                            item.unlink()
                except PermissionError as e:
                    logging.error(f'Permission error while clearing benchmark directory: {e}')
                    raise
                except Exception as e:
                    logging.error(f'Error while clearing benchmark directory: {e}')
                    raise
            
            # Extract new benchmark
            try:
                result = subprocess.run(
                    ['unzip', '-o', str(zip_file), '-d', str(self.benchmark_dir)], 
                    check=True, capture_output=True, text=True
                )
                logging.info(f'Successfully extracted {zip_file.name}')
                logging.debug(f'Unzip output: {result.stdout}')
            except subprocess.CalledProcessError as e:
                logging.error(f'Error extracting zip file: {e.stderr}')
                raise
            except Exception as e:
                logging.error(f'Unexpected error during extraction: {str(e)}')
                raise
                
        except Exception as e:
            logging.error(f'Error processing STIG benchmark: {str(e)}')
            raise

    def find_benchmark_xml(self):
        """Find the XCCDF benchmark XML file in the extracted contents."""
        for file in self.benchmark_dir.rglob('*xccdf.xml'):
            return file
        raise FileNotFoundError('No XCCDF benchmark XML file found in the extracted contents')

    def analyze_report(self, xml_path):
        """Analyze the XML report and return a summary of compliance results."""
        try:
            result = subprocess.run(
                ['oscap', 'xccdf', 'generate', 'report', str(xml_path)],
                capture_output=True, text=True, check=True
            )
            
            # Parse the results to get pass/fail counts
            passed = result.stdout.count('pass')
            failed = result.stdout.count('fail')
            total = passed + failed
            
            return {
                'passed': passed,
                'failed': failed,
                'total': total,
                'compliance_rate': (passed / total * 100) if total > 0 else 0
            }
        except subprocess.CalledProcessError as e:
            logging.error(f"Error analyzing report: {e}")
            return None

    def run_scan(self):
        """Execute STIG compliance scan."""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = self.reports_dir / f'stig_report_{timestamp}'
        
        try:
            # Find the benchmark XML file
            benchmark_path = self.find_benchmark_xml()
            logging.info(f'Using benchmark file: {benchmark_path}')
            
            # Run OpenSCAP scan
            # First list available profiles
            profile_list = subprocess.run(
                ['oscap', 'info', str(benchmark_path)],
                capture_output=True, text=True, check=True
            )
            logging.info("Available profiles:")
            logging.info(profile_list.stdout)
            
            # Run the scan with more verbose output
            result = subprocess.run([
                'oscap', 'xccdf', 'eval',
                '--verbose', 'INFO',
                '--profile', self.profile_name,
                '--results', f'{str(report_path)}.xml',
                '--report', f'{str(report_path)}.html',
                str(benchmark_path)
            ], capture_output=True, text=True)
            
            logging.info("STDOUT:")
            logging.info(result.stdout)
            logging.info("\nSTDERR:")
            logging.info(result.stderr)
            
            if result.returncode != 0:
                logging.error(f"\nScan completed with return code: {result.returncode}")
                return False
            
            # Analyze the results
            analysis = self.analyze_report(f'{str(report_path)}.xml')
            if analysis:
                logging.info("Scan Analysis:")
                logging.info(f"Total Rules: {analysis['total']}")
                logging.info(f"Passed: {analysis['passed']}")
                logging.info(f"Failed: {analysis['failed']}")
                logging.info(f"Compliance Rate: {analysis['compliance_rate']:.2f}%")
            
            logging.info(f"Scan completed successfully. Reports saved to {report_path}.xml and {report_path}.html")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Error during scan: {e}")
            return False

def main():
    # Set up argument parser
    import argparse
    parser = argparse.ArgumentParser(description='STIG Compliance Scanner')
    parser.add_argument('--profile', default='MAC-1_Public',
                        help='STIG profile to use for scanning (default: MAC-1_Public)')
    args = parser.parse_args()
    
    scanner = STIGScanner(profile_name=args.profile)
    
    # Run scan immediately
    logging.info("Running STIG compliance scan...")
    try:
        scanner.extract_stig_benchmark()
        success = scanner.run_scan()
        if success:
            logging.info("Scan completed successfully")
            sys.exit(0)
        else:
            logging.error("Scan failed")
            sys.exit(1)
    except Exception as e:
        logging.error(f"Error during scan: {str(e)}")
        sys.exit(1)

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
