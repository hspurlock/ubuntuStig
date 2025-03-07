# Docker STIG Compatibility Feature

## Overview

The Docker STIG Compatibility feature provides a specialized STIG compliance script tailored for Docker container environments. This feature analyzes the standard Ubuntu STIG compliance checks and filters out checks that are not applicable to containerized environments, while preserving and adapting relevant security controls.

## Problem Statement

Standard STIG compliance scripts are designed for traditional operating system installations and include many checks that are not applicable to Docker containers, such as:

- System service checks (systemd, init)
- Kernel parameter configurations
- Boot loader configurations
- Hardware-specific settings
- GUI-related settings
- Host-level security controls (AppArmor, firewall)

Running these checks in a Docker container environment leads to:
1. False negatives (failing checks that aren't relevant)
2. Misleading compliance scores
3. Confusion about which security controls to implement

## Solution

The Docker STIG filter script (`generate_Docker_stig_script.py`) addresses these issues by:

1. Analyzing the standard STIG compliance checks
2. Filtering out checks that are not applicable to Docker containers
3. Adapting relevant checks to work properly in a containerized environment
4. Generating a Docker-compatible STIG compliance script

### Key Features

#### 1. Intelligent Filtering

The script identifies Docker-incompatible checks using pattern matching against:
- Command patterns (e.g., systemctl, mount, sysctl)
- Title keywords (e.g., "audit", "boot", "systemd")
- Check content analysis

#### 2. Command Adaptation

Commands are modified to work better in Docker environments:
- Removing sudo prefixes (containers often run as root)
- Adjusting paths for Docker filesystem layouts
- Handling Docker-specific environment variables

#### 3. Conditional SSH Checks

SSH-related checks are conditionally evaluated:
- Checks if SSH is installed before evaluating SSH banner requirements
- Marks checks as "NOT_CHECKED" with appropriate messaging when SSH is not installed
- Properly evaluates SSH banner requirements when SSH is installed

#### 4. Comprehensive Exclusions

The script excludes checks related to:
- AppArmor (managed at host level)
- PAM modules (not relevant in containers)
- Sudo configuration (not typically used in containers)
- Chrony/time synchronization (inherited from host)
- PIV credentials (not applicable in containers)
- Session locking (containers don't support interactive sessions)

## Implementation Details

### Pattern Lists

The script maintains two comprehensive pattern lists:
- `DOCKER_INCOMPATIBLE_PATTERNS`: Patterns indicating a check is not compatible with Docker
- `DOCKER_COMPATIBLE_PATTERNS`: Patterns indicating a check is compatible with Docker

### Key Functions

1. `is_docker_compatible()`: Determines if a STIG check is compatible with Docker containers
2. `fix_command_for_docker()`: Modifies commands to work better in Docker environments
3. `generate_check_block()`: Generates shell script blocks for STIG checks, with special handling for SSH-related checks
4. `modify_check_block_for_docker()`: Adapts check blocks for Docker compatibility

### SSH Check Handling

For SSH-related checks (e.g., SSH banner requirements), the script:
1. Detects SSH-related checks based on the title
2. Adds a conditional check to verify if SSH is installed:
   ```bash
   # Check if SSH is installed
   if ! dpkg -l | grep -q openssh-server; then
       # SSH is not installed, so this check is not applicable
       result="NOT_CHECKED"
       echo -e "${YELLOW}SSH is not installed, skipping this check${NC}"
   else
       # Perform the regular SSH check
       ...
   fi
   ```
3. Only evaluates SSH banner requirements if SSH is actually installed

## Usage

```bash
python3 generate_Docker_stig_script.py <input_xml_file> <output_script_file>
```

Example:
```bash
python3 generate_Docker_stig_script.py U_CAN_Ubuntu_24-04_LTS_STIG_V1R1_Manual-xccdf.xml docker_ubuntu_24-04_v1r1.sh
```

## Benefits

1. **Accurate Compliance Assessment**: Provides a more accurate assessment of container security posture by excluding irrelevant checks
2. **Reduced False Negatives**: Eliminates failing checks that don't apply to containers
3. **Better Alignment with Container Security**: Focuses on security controls that are relevant in containerized environments
4. **Conditional Evaluation**: Intelligently evaluates checks based on the container's configuration (e.g., SSH installation)
5. **Clear Feedback**: Provides clear messaging about why certain checks are skipped

## Future Enhancements

Potential future enhancements include:
1. Adding more container-specific security checks
2. Supporting different container runtimes (Podman, LXC)
3. Integration with container orchestration platforms (Kubernetes, Docker Swarm)
4. Enhanced reporting with container-specific recommendations
