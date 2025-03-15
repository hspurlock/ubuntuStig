# Container STIG Compatibility Feature

## Overview

The Container STIG Compatibility feature generates compliance scripts tailored specifically for container environments. This feature intelligently filters out checks that are not applicable to containers and adapts relevant checks to work properly in containerized environments.

## Purpose

Containers have a different security model compared to traditional operating systems. Many STIG checks that apply to full operating systems are not relevant or cannot be implemented in containers due to their isolated and minimal nature. This feature ensures that only applicable checks are included in container compliance assessments, providing more accurate and relevant security evaluations.

## Key Features

### Intelligent Filtering

The Container STIG script generator automatically excludes checks that are not applicable to containers, including:

- **Systemd-related checks**: Containers typically don't use systemd for service management
- **Boot configuration**: Container images don't have traditional boot processes
- **Kernel parameters**: Most kernel parameters cannot be modified from within containers
- **Hardware-specific checks**: Containers share the host's hardware abstraction

### Conditional SSH Checks

The script only evaluates SSH banner requirements if SSH is installed in the container. This prevents false failures for containers that don't include SSH services.

### Comprehensive Exclusions

The generator specifically excludes checks related to:

- AppArmor profiles (managed by the host)
- PAM configurations (not applicable in most containers)
- Sudo configurations (often not installed in containers)
- Chrony/NTP (time synchronization handled by the host)
- PIV credentials (not applicable in container environments)
- Session locking (not relevant for containerized applications)

### Command Handling Improvements

The Container STIG script includes specialized command handling for container environments:

- **Enhanced grep command handling**: Properly escapes regex patterns in grep commands
- **Maxlogins configuration checks**: Special handling for checking maxlogins settings
- **Improved command evaluation**: Intelligently evaluates command results based on command type and output

## Usage

### Generating Container-Compatible STIG Scripts

```bash
python3 utils/generate_Container_stig_script.py <xml_file> <output_script_file>
```

Example:
```bash
python3 utils/generate_Container_stig_script.py U_CAN_Ubuntu_24-04_LTS_STIG_V1R1_Manual-xccdf.xml container_ubuntu_24-04_v1r1.sh
```

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

## Benefits

Using the Container STIG compatibility feature provides several benefits:

1. **More Accurate Compliance Scores**: By excluding irrelevant checks, the compliance score better reflects the actual security posture of the container.

2. **Reduced False Positives**: Prevents failures on checks that cannot be implemented in containers.

3. **Focused Remediation**: Security teams can focus on addressing relevant findings rather than spending time on inapplicable issues.

4. **Container-Specific Security**: Emphasizes security controls that are meaningful in containerized environments.

5. **Improved Command Handling**: Special handling for complex commands ensures accurate check results.

## Implementation Details

The Container STIG script generator implements filtering through several mechanisms:

1. **Rule ID Filtering**: Excludes specific rules known to be inapplicable to containers
2. **Content Analysis**: Examines check content for references to systemd, boot configurations, etc.
3. **Command Analysis**: Analyzes commands to determine if they reference host-specific resources
4. **Special Case Handling**: Implements special handling for commands that need adaptation for container environments

## Future Enhancements

Planned enhancements for the Container STIG compatibility feature include:

1. **Container-Specific Checks**: Adding container-specific security checks not covered by standard STIGs
2. **Container Orchestration Integration**: Support for Kubernetes and other orchestration environments
3. **Container Image Analysis**: Pre-deployment scanning of container images
4. **Remediation Scripts**: Automated remediation for container-specific findings
