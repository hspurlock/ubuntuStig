#!/usr/bin/env python3

import subprocess
import os
import datetime
import schedule
import time
import json
import pandas as pd
import matplotlib.pyplot as plt
import docker
from pathlib import Path
from jinja2 import Template

class STIGScanner:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.reports_dir = self.base_dir / 'reports'
        self.reports_dir.mkdir(exist_ok=True)
        self.docker_client = docker.from_env()
        
        # Ensure OpenSCAP is installed
        self._check_dependencies()

    def _check_dependencies(self):
        """Check if required system dependencies are installed."""
        try:
            subprocess.run(['oscap', '--version'], check=True, capture_output=True)
            # Check Docker availability
            self.docker_client.ping()
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("OpenSCAP not found. Installing required packages...")
            subprocess.run(['sudo', 'apt-get', 'update'], check=True)
            subprocess.run(['sudo', 'apt-get', 'install', '-y', 'libopenscap8', 'openscap-scanner', 'ssg-base', 'ssg-debderived'], check=True)
        except docker.errors.APIError:
            print("Warning: Docker daemon is not accessible. Docker container scanning will be disabled.")

    def download_stig_benchmark(self):
        """Download the latest DISA STIG for Ubuntu 22.04."""
        benchmark_url = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_22-04_LTS_V1R1_STIG_SCAP_1-2_Benchmark.zip"
        benchmark_dir = self.base_dir / 'benchmarks'
        benchmark_dir.mkdir(exist_ok=True)
        
        # Download and extract benchmark
        subprocess.run(['wget', benchmark_url, '-P', str(benchmark_dir)], check=True)
        subprocess.run(['unzip', '-o', str(benchmark_dir / '*.zip'), '-d', str(benchmark_dir)], check=True)

    def run_scan(self):
        """Execute STIG compliance scan."""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = self.reports_dir / f'stig_report_{timestamp}'
        
        # Run OpenSCAP scan
        subprocess.run([
            'sudo', 'oscap', 'xccdf', 'eval',
            '--profile', 'xccdf_mil.disa.stig_profile_default',
            '--results', f'{report_path}.xml',
            '--report', f'{report_path}.html',
            str(self.base_dir / 'benchmarks' / 'U_CAN_Ubuntu_22-04_LTS_V1R1_STIG_SCAP_1-2_Benchmark.xml')
        ], check=True)
        
        return report_path

    def scan_docker_containers(self):
        """Scan running Docker containers for security issues."""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        docker_report = {
            'timestamp': timestamp,
            'containers': []
        }

        try:
            containers = self.docker_client.containers.list()
            for container in containers:
                container_info = container.attrs
                security_issues = []

                # Check for common security issues
                if not container_info['HostConfig'].get('ReadonlyRootfs', False):
                    security_issues.append("Container root filesystem is not read-only")
                
                if container_info['HostConfig'].get('Privileged', False):
                    security_issues.append("Container is running in privileged mode")

                if not container_info['Config'].get('User'):
                    security_issues.append("Container is running as root user")

                # Check network mode
                if container_info['HostConfig'].get('NetworkMode') == 'host':
                    security_issues.append("Container is using host network mode")

                # Check mount points for sensitive paths
                mounts = container_info['Mounts']
                for mount in mounts:
                    if mount['Type'] == 'bind' and any(
                        sensitive in mount['Source'] 
                        for sensitive in ['/etc', '/usr', '/bin', '/sbin']
                    ):
                        security_issues.append(f"Sensitive host path mounted: {mount['Source']}")

                container_report = {
                    'container_id': container.id,
                    'name': container.name,
                    'image': container.image.tags[0] if container.image.tags else 'untagged',
                    'status': container.status,
                    'security_issues': security_issues
                }
                docker_report['containers'].append(container_report)

            # Save Docker scan results
            report_path = self.reports_dir / f'docker_scan_{timestamp}.json'
            with open(report_path, 'w') as f:
                json.dump(docker_report, f, indent=4)

            return report_path

        except docker.errors.APIError as e:
            print(f"Error scanning Docker containers: {e}")
            return None

    def generate_monthly_report(self):
        """Generate monthly compliance report with trends."""
        reports = sorted(self.reports_dir.glob('stig_report_*.xml'))
        if not reports:
            print("No reports found to generate monthly summary")
            return

        # Parse results and create trends
        results = []
        for report in reports:
            # Parse XML report and extract compliance data
            # This is a simplified example - you would need to implement XML parsing
            results.append({
                'date': report.stem.split('_')[2],
                'compliant': 0,
                'non_compliant': 0,
                'total': 0
            })

        # Create trend visualization
        df = pd.DataFrame(results)
        plt.figure(figsize=(10, 6))
        plt.plot(df['date'], df['compliant'] / df['total'] * 100)
        plt.title('STIG Compliance Trend')
        plt.xlabel('Date')
        plt.ylabel('Compliance %')
        plt.savefig(self.reports_dir / 'compliance_trend.png')

def main():
    scanner = STIGScanner()
    
    # Schedule scans
    schedule.every().month.at("00:00").do(scanner.run_scan)
    schedule.every().month.at("01:00").do(scanner.generate_monthly_report)
    schedule.every().day.at("02:00").do(scanner.scan_docker_containers)
    
    # Run initial scan
    print("Running initial STIG compliance scan...")
    scanner.download_stig_benchmark()
    scanner.run_scan()
    scanner.generate_monthly_report()
    scanner.scan_docker_containers()
    
    # Run scheduled tasks
    while True:
        schedule.run_pending()
        time.sleep(60)  # Check every minute

if __name__ == "__main__":
    import sys
    import logging
    import systemd.daemon
    import systemd.journal

    # Set up logging to systemd journal
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger()
    logger.addHandler(systemd.journal.JournalHandler())

    try:
        logger.info("Starting Ubuntu STIG Scanner service")
        systemd.daemon.notify('READY=1')
        main()
    except KeyboardInterrupt:
        logger.info("Service stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Service error: {str(e)}")
        sys.exit(1)
