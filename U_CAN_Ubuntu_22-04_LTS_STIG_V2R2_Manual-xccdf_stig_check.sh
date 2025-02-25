#!/bin/bash

# STIG Compliance Check Script
# Generated from XCCDF file: U_CAN_Ubuntu_22-04_LTS_STIG_V2R2_Manual-xccdf.xml

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root to perform all checks properly."
    echo "Please run with: sudo $0"
    exit 1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Results array
declare -A results
declare -A titles

# Trap Ctrl+C and cleanup
trap cleanup INT

cleanup() {
    echo -e "\n\nScript interrupted. Generating report with current results..."
    generate_report
    exit 1
}

run_check() {
    local cmd="$1"
    
    # Check if command contains placeholders (e.g., <user>)
    if [[ "$cmd" == *"<"*">"* ]]; then
        echo "manual"
        return
    fi
    
    # Execute command with a timeout
    timeout 5s bash -c "$cmd" &>/dev/null
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        echo "pass"
    elif [ $exit_code -eq 124 ]; then
        # Command timed out
        echo "manual"
    else
        echo "fail"
    fi
}

log_result() {
    local rule_id="$1"
    local status="$2"
    local title="$3"
    
    if [ "$status" == "pass" ]; then
        echo -e "${GREEN}[PASS]${NC} $rule_id: $title"
        results["$rule_id"]="pass"
    elif [ "$status" == "manual" ]; then
        echo -e "${YELLOW}[MANUAL CHECK NEEDED]${NC} $rule_id: $title"
        results["$rule_id"]="manual"
    else
        echo -e "${RED}[FAIL]${NC} $rule_id: $title"
        results["$rule_id"]="fail"
    fi
    titles["$rule_id"]="$title"
}

generate_report() {
    # Generate summary report
    echo -e "\nSTIG Compliance Summary Report"
    echo "================================"
    echo -e "Total Rules Checked: ${#results[@]}"
    pass_count=$(echo "${results[@]}" | tr ' ' '\n' | grep -c "pass" || echo 0)
    manual_count=$(echo "${results[@]}" | tr ' ' '\n' | grep -c "manual" || echo 0)
    fail_count=$(echo "${results[@]}" | tr ' ' '\n' | grep -c "fail" || echo 0)
    echo -e "Passed: $pass_count"
    echo -e "Failed: $fail_count"
    echo -e "Manual Checks Needed: $manual_count"

    # Create results directory with proper permissions
    RESULTS_DIR="stig_results"
    mkdir -p "$RESULTS_DIR"
    chmod 755 "$RESULTS_DIR"

    # Generate HTML report
    cat > "$RESULTS_DIR/report.html" << 'EOL'
<!DOCTYPE html>
<html>
<head>
    <title>STIG Compliance Report</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 20px; 
            line-height: 1.6;
            color: #333;
        }
        h1, h2 { 
            color: #2c3e50; 
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }
        .summary { 
            background: #f8f9fa; 
            padding: 20px; 
            border-radius: 8px; 
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .pass { color: #28a745; }
        .fail { color: #dc3545; }
        .manual { color: #ffc107; }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th, td { 
            padding: 12px 15px; 
            text-align: left; 
            border-bottom: 1px solid #dee2e6; 
        }
        th { 
            background: #f8f9fa; 
            font-weight: bold;
            color: #2c3e50;
        }
        tr:hover { background: #f8f9fa; }
        .status-badge {
            padding: 6px 12px;
            border-radius: 4px;
            font-weight: bold;
            display: inline-block;
            min-width: 80px;
            text-align: center;
        }
        .status-pass { background: #d4edda; color: #155724; }
        .status-fail { background: #f8d7da; color: #721c24; }
        .status-manual { background: #fff3cd; color: #856404; }
        .timestamp {
            margin-top: 20px;
            color: #6c757d;
            font-style: italic;
        }
        .title-cell {
            max-width: 600px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
    </style>
</head>
<body>
    <h1>STIG Compliance Report</h1>
EOL

    # Add summary section
    cat >> "$RESULTS_DIR/report.html" << EOL
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Rules Checked:</strong> ${#results[@]}</p>
        <p class="pass"><strong>Passed:</strong> $pass_count</p>
        <p class="fail"><strong>Failed:</strong> $fail_count</p>
        <p class="manual"><strong>Manual Checks Needed:</strong> $manual_count</p>
    </div>
    <h2>Detailed Results</h2>
    <table>
        <tr>
            <th>Rule ID</th>
            <th>Title</th>
            <th>Status</th>
        </tr>
EOL

    # Add results to the HTML table
    for rule_id in "${!results[@]}"; do
        status="${results[$rule_id]}"
        title="${titles[$rule_id]}"
        case $status in
            "pass")
                status_class="status-pass"
                ;;
            "fail")
                status_class="status-fail"
                ;;
            "manual")
                status_class="status-manual"
                ;;
        esac
        echo "        <tr>" >> "$RESULTS_DIR/report.html"
        echo "            <td>$rule_id</td>" >> "$RESULTS_DIR/report.html"
        echo "            <td class='title-cell'>$title</td>" >> "$RESULTS_DIR/report.html"
        echo "            <td><span class='status-badge $status_class'>${status^^}</span></td>" >> "$RESULTS_DIR/report.html"
        echo "        </tr>" >> "$RESULTS_DIR/report.html"
    done

    # Add footer with timestamp
    cat >> "$RESULTS_DIR/report.html" << EOL
    </table>
    <p class="timestamp">Report generated on $(date)</p>
</body>
</html>
EOL

    chmod 644 "$RESULTS_DIR/report.html"

    echo -e "\nDetailed results have been saved to $RESULTS_DIR/report.html"
}

# SV-260469r991589_rule: Ubuntu 22.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence.
check_SV_260469r991589_rule() {
    local status="fail"

    # Run command: systemctl status ctrl-alt-del.target
    status=$(run_check "systemctl status ctrl-alt-del.target")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260469r991589_rule" "$status" "Ubuntu 22.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence."
}

# SV-260470r958472_rule: Ubuntu 22.04 LTS, when booted, must require authentication upon booting into single-user and maintenance modes.
check_SV_260470r958472_rule() {
    local status="fail"

    # Run command: sudo grep -i password /boot/grub/grub.cfg
    status=$(run_check "grep -i password /boot/grub/grub.cfg")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260470r958472_rule" "$status" "Ubuntu 22.04 LTS, when booted, must require authentication upon booting into single-user and maintenance modes."
}

# SV-260471r991555_rule: Ubuntu 22.04 LTS must initiate session audits at system startup.
check_SV_260471r991555_rule() {
    local status="fail"

    # Run command: grep "^\s*linux" /boot/grub/grub.cfg
    status=$(run_check "grep \"^\s*linux\" /boot/grub/grub.cfg")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260471r991555_rule" "$status" "Ubuntu 22.04 LTS must initiate session audits at system startup."
}

# SV-260472r958524_rule: Ubuntu 22.04 LTS must restrict access to the kernel message buffer.
check_SV_260472r958524_rule() {
    local status="fail"

    # Run command: sysctl kernel.dmesg_restrict
    status=$(run_check "sysctl kernel.dmesg_restrict")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo grep -ir kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
    status=$(run_check "grep -ir kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260472r958524_rule" "$status" "Ubuntu 22.04 LTS must restrict access to the kernel message buffer."
}

# SV-260473r958550_rule: Ubuntu 22.04 LTS must disable kernel core dumps so that it can fail to a secure state if system initialization fails, shutdown fails or aborts fail.
check_SV_260473r958550_rule() {
    local status="fail"

    # Run command: systemctl status kdump.service
    status=$(run_check "systemctl status kdump.service")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260473r958550_rule" "$status" "Ubuntu 22.04 LTS must disable kernel core dumps so that it can fail to a secure state if system initialization fails, shutdown fails or aborts fail."
}

# SV-260474r958928_rule: Ubuntu 22.04 LTS must implement address space layout randomization to protect its memory from unauthorized code execution.
check_SV_260474r958928_rule() {
    local status="fail"

    # Run command: sysctl kernel.randomize_va_space
    status=$(run_check "sysctl kernel.randomize_va_space")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: cat /proc/sys/kernel/randomize_va_space
    status=$(run_check "cat /proc/sys/kernel/randomize_va_space")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo grep -ER "^kernel.randomize_va_space=[^2]" /etc/sysctl.conf /etc/sysctl.d
    status=$(run_check "grep -ER \"^kernel.randomize_va_space=[^2]\" /etc/sysctl.conf /etc/sysctl.d")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260474r958928_rule" "$status" "Ubuntu 22.04 LTS must implement address space layout randomization to protect its memory from unauthorized code execution."
}

# SV-260475r958928_rule: Ubuntu 22.04 LTS must implement nonexecutable data to protect its memory from unauthorized code execution.
check_SV_260475r958928_rule() {
    local status="fail"

    # Run command: sudo dmesg | grep -i "execute disable"
    status=$(run_check "dmesg | grep -i \"execute disable\"")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: grep flags /proc/cpuinfo | grep -o nx | sort -u
    status=$(run_check "grep flags /proc/cpuinfo | grep -o nx | sort -u")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260475r958928_rule" "$status" "Ubuntu 22.04 LTS must implement nonexecutable data to protect its memory from unauthorized code execution."
}

# SV-260476r1015003_rule: Ubuntu 22.04 LTS must be configured so that the Advance Package Tool (APT) prevents the installation of patches, service packs, device drivers, or operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.
check_SV_260476r1015003_rule() {
    local status="fail"

    # Run command: grep -i allowunauthenticated /etc/apt/apt.conf.d/*
    status=$(run_check "grep -i allowunauthenticated /etc/apt/apt.conf.d/*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260476r1015003_rule" "$status" "Ubuntu 22.04 LTS must be configured so that the Advance Package Tool (APT) prevents the installation of patches, service packs, device drivers, or operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization."
}

# SV-260477r958936_rule: Ubuntu 22.04 LTS must be configured so that the Advance Package Tool (APT) removes all software components after updated versions have been installed.
check_SV_260477r958936_rule() {
    local status="fail"

    # Run command: grep -i remove-unused /etc/apt/apt.conf.d/50-unattended-upgrades
    status=$(run_check "grep -i remove-unused /etc/apt/apt.conf.d/50-unattended-upgrades")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260477r958936_rule" "$status" "Ubuntu 22.04 LTS must be configured so that the Advance Package Tool (APT) removes all software components after updated versions have been installed."
}

# SV-260478r991587_rule: Ubuntu 22.04 LTS must have the "libpam-pwquality" package installed.
check_SV_260478r991587_rule() {
    local status="fail"

    # Run command: dpkg -l | grep libpam-pwquality
    status=$(run_check "dpkg -l | grep libpam-pwquality")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260478r991587_rule" "$status" "Ubuntu 22.04 LTS must have the "libpam-pwquality" package installed."
}

# SV-260479r991589_rule: Ubuntu 22.04 LTS must have the "chrony" package installed.
check_SV_260479r991589_rule() {
    local status="fail"

    # Run command: dpkg -l | grep chrony
    status=$(run_check "dpkg -l | grep chrony")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260479r991589_rule" "$status" "Ubuntu 22.04 LTS must have the "chrony" package installed."
}

# SV-260480r991589_rule: Ubuntu 22.04 LTS must not have the "systemd-timesyncd" package installed.
check_SV_260480r991589_rule() {
    local status="fail"

    # Run command: dpkg -l | grep systemd-timesyncd
    status=$(run_check "dpkg -l | grep systemd-timesyncd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260480r991589_rule" "$status" "Ubuntu 22.04 LTS must not have the "systemd-timesyncd" package installed."
}

# SV-260481r991589_rule: Ubuntu 22.04 LTS must not have the "ntp" package installed.
check_SV_260481r991589_rule() {
    local status="fail"

    # Run command: dpkg -l | grep ntp
    status=$(run_check "dpkg -l | grep ntp")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260481r991589_rule" "$status" "Ubuntu 22.04 LTS must not have the "ntp" package installed."
}

# SV-260482r958478_rule: Ubuntu 22.04 LTS must not have the "rsh-server" package installed.
check_SV_260482r958478_rule() {
    local status="fail"

    # Run command: dpkg -l | grep rsh-server
    status=$(run_check "dpkg -l | grep rsh-server")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260482r958478_rule" "$status" "Ubuntu 22.04 LTS must not have the "rsh-server" package installed."
}

# SV-260483r987796_rule: Ubuntu 22.04 LTS must not have the "telnet" package installed.
check_SV_260483r987796_rule() {
    local status="fail"

    # Run command: dpkg -l | grep telnetd
    status=$(run_check "dpkg -l | grep telnetd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260483r987796_rule" "$status" "Ubuntu 22.04 LTS must not have the "telnet" package installed."
}

# SV-260484r958552_rule: Ubuntu 22.04 LTS must implement cryptographic mechanisms to prevent unauthorized disclosure and modification of all information that requires protection at rest.
check_SV_260484r958552_rule() {
    local status="fail"

    # Run command: sudo fdisk -l
    status=$(run_check "fdisk -l")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260484r958552_rule" "$status" "Ubuntu 22.04 LTS must implement cryptographic mechanisms to prevent unauthorized disclosure and modification of all information that requires protection at rest."
}

# SV-260485r991559_rule: Ubuntu 22.04 LTS must have directories that contain system commands set to a mode of "755" or less permissive.
check_SV_260485r991559_rule() {
    local status="fail"

    # Run command: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" '{}' \;
    status=$(run_check "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c \"%n %a\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260485r991559_rule" "$status" "Ubuntu 22.04 LTS must have directories that contain system commands set to a mode of "755" or less permissive."
}

# SV-260486r991560_rule: Ubuntu 22.04 LTS must have system commands set to a mode of "755" or less permissive.
check_SV_260486r991560_rule() {
    local status="fail"

    # Run command: sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c "%n %a" '{}' \;
    status=$(run_check "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c \"%n %a\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260486r991560_rule" "$status" "Ubuntu 22.04 LTS must have system commands set to a mode of "755" or less permissive."
}

# SV-260487r991560_rule: Ubuntu 22.04 LTS library files must have mode "755" or less permissive.
check_SV_260487r991560_rule() {
    local status="fail"

    # Run command: sudo find /lib /lib64 /usr/lib -perm /022 -type f -exec stat -c "%n %a" '{}' \;
    status=$(run_check "find /lib /lib64 /usr/lib -perm /022 -type f -exec stat -c \"%n %a\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260487r991560_rule" "$status" "Ubuntu 22.04 LTS library files must have mode "755" or less permissive."
}

# SV-260488r958566_rule: Ubuntu 22.04 LTS must configure the "/var/log" directory to have mode "755" or less permissive.
check_SV_260488r958566_rule() {
    local status="fail"

    # Run command: stat -c "%n %a" /var/log
    status=$(run_check "stat -c \"%n %a\" /var/log")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260488r958566_rule" "$status" "Ubuntu 22.04 LTS must configure the "/var/log" directory to have mode "755" or less permissive."
}

# SV-260489r958564_rule: Ubuntu 22.04 LTS must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.
check_SV_260489r958564_rule() {
    local status="fail"

    # Run command: sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c "%n %a" {} \;
    status=$(run_check "find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c \"%n %a\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260489r958564_rule" "$status" "Ubuntu 22.04 LTS must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries."
}

# SV-260490r1014781_rule: Ubuntu 22.04 LTS must generate system journal entries without revealing information that could be exploited by adversaries.
check_SV_260490r1014781_rule() {
    local status="fail"

    # Run command: sudo find /run/log/journal /var/log/journal -type d -exec stat -c "%n %a" {} \;
    status=$(run_check "find /run/log/journal /var/log/journal -type d -exec stat -c \"%n %a\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %a" {} \;
    status=$(run_check "find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %a\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260490r1014781_rule" "$status" "Ubuntu 22.04 LTS must generate system journal entries without revealing information that could be exploited by adversaries."
}

# SV-260491r958566_rule: Ubuntu 22.04 LTS must configure "/var/log/syslog" file with mode "640" or less permissive.
check_SV_260491r958566_rule() {
    local status="fail"

    # Run command: stat -c "%n %a" /var/log/syslog
    status=$(run_check "stat -c \"%n %a\" /var/log/syslog")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260491r958566_rule" "$status" "Ubuntu 22.04 LTS must configure "/var/log/syslog" file with mode "640" or less permissive."
}

# SV-260492r991557_rule: Ubuntu 22.04 LTS must configure audit tools with a mode of "755" or less permissive.
check_SV_260492r991557_rule() {
    local status="fail"

    # Run command: stat -c "%n %a" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules
    status=$(run_check "stat -c \"%n %a\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260492r991557_rule" "$status" "Ubuntu 22.04 LTS must configure audit tools with a mode of "755" or less permissive."
}

# SV-260493r991559_rule: Ubuntu 22.04 LTS must have directories that contain system commands owned by "root".
check_SV_260493r991559_rule() {
    local status="fail"

    # Run command: sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' \;
    status=$(run_check "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c \"%n %U\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260493r991559_rule" "$status" "Ubuntu 22.04 LTS must have directories that contain system commands owned by "root"."
}

# SV-260494r991559_rule: Ubuntu 22.04 LTS must have directories that contain system commands group-owned by "root".
check_SV_260494r991559_rule() {
    local status="fail"

    # Run command: sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c "%n %G" '{}' \;
    status=$(run_check "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c \"%n %G\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260494r991559_rule" "$status" "Ubuntu 22.04 LTS must have directories that contain system commands group-owned by "root"."
}

# SV-260495r991560_rule: Ubuntu 22.04 LTS must have system commands owned by "root" or a system account.
check_SV_260495r991560_rule() {
    local status="fail"

    # Run command: sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c "%n %U" '{}' \;
    status=$(run_check "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c \"%n %U\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260495r991560_rule" "$status" "Ubuntu 22.04 LTS must have system commands owned by "root" or a system account."
}

# SV-260496r991560_rule: Ubuntu 22.04 LTS must have system commands group-owned by "root" or a system account.
check_SV_260496r991560_rule() {
    local status="fail"

    # Run command: sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f ! -perm /2000 -exec stat -c "%n %G" '{}' \;
    status=$(run_check "find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f ! -perm /2000 -exec stat -c \"%n %G\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260496r991560_rule" "$status" "Ubuntu 22.04 LTS must have system commands group-owned by "root" or a system account."
}

# SV-260497r991560_rule: Ubuntu 22.04 LTS library directories must be owned by "root".
check_SV_260497r991560_rule() {
    local status="fail"

    # Run command: sudo find /lib /usr/lib /lib64 ! -user root -type d -exec stat -c "%n %U" '{}' \;
    status=$(run_check "find /lib /usr/lib /lib64 ! -user root -type d -exec stat -c \"%n %U\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260497r991560_rule" "$status" "Ubuntu 22.04 LTS library directories must be owned by "root"."
}

# SV-260498r991560_rule: Ubuntu 22.04 LTS library directories must be group-owned by "root".
check_SV_260498r991560_rule() {
    local status="fail"

    # Run command: sudo find /lib /usr/lib /lib64 ! -group root -type d -exec stat -c "%n %G" '{}' \;
    status=$(run_check "find /lib /usr/lib /lib64 ! -group root -type d -exec stat -c \"%n %G\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260498r991560_rule" "$status" "Ubuntu 22.04 LTS library directories must be group-owned by "root"."
}

# SV-260499r991560_rule: Ubuntu 22.04 LTS library files must be owned by "root".
check_SV_260499r991560_rule() {
    local status="fail"

    # Run command: sudo find /lib /usr/lib /lib64 ! -user root -type f -exec stat -c "%n %U" '{}' \;
    status=$(run_check "find /lib /usr/lib /lib64 ! -user root -type f -exec stat -c \"%n %U\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260499r991560_rule" "$status" "Ubuntu 22.04 LTS library files must be owned by "root"."
}

# SV-260500r991560_rule: Ubuntu 22.04 LTS library files must be group-owned by "root".
check_SV_260500r991560_rule() {
    local status="fail"

    # Run command: sudo find /lib /usr/lib /lib64 ! -group root -type f -exec stat -c "%n %G" '{}' \;
    status=$(run_check "find /lib /usr/lib /lib64 ! -group root -type f -exec stat -c \"%n %G\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260500r991560_rule" "$status" "Ubuntu 22.04 LTS library files must be group-owned by "root"."
}

# SV-260501r958566_rule: Ubuntu 22.04 LTS must configure the directories used by the system journal to be owned by "root".
check_SV_260501r958566_rule() {
    local status="fail"

    # Run command: sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %U" {} \;
    status=$(run_check "find /run/log/journal /var/log/journal  -type d -exec stat -c \"%n %U\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260501r958566_rule" "$status" "Ubuntu 22.04 LTS must configure the directories used by the system journal to be owned by "root"."
}

# SV-260502r958566_rule: Ubuntu 22.04 LTS must configure the directories used by the system journal to be group-owned by "systemd-journal".
check_SV_260502r958566_rule() {
    local status="fail"

    # Run command: sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %G" {} \;
    status=$(run_check "find /run/log/journal /var/log/journal  -type d -exec stat -c \"%n %G\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260502r958566_rule" "$status" "Ubuntu 22.04 LTS must configure the directories used by the system journal to be group-owned by "systemd-journal"."
}

# SV-260503r958566_rule: Ubuntu 22.04 LTS must configure the files used by the system journal to be owned by "root".
check_SV_260503r958566_rule() {
    local status="fail"

    # Run command: sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %U" {} \;
    status=$(run_check "find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %U\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260503r958566_rule" "$status" "Ubuntu 22.04 LTS must configure the files used by the system journal to be owned by "root"."
}

# SV-260504r958566_rule: Ubuntu 22.04 LTS must configure the files used by the system journal to be group-owned by "systemd-journal".
check_SV_260504r958566_rule() {
    local status="fail"

    # Run command: sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %G" {} \;
    status=$(run_check "find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %G\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260504r958566_rule" "$status" "Ubuntu 22.04 LTS must configure the files used by the system journal to be group-owned by "systemd-journal"."
}

# SV-260505r958566_rule: Ubuntu 22.04 LTS must be configured so that the "journalctl" command is owned by "root".
check_SV_260505r958566_rule() {
    local status="fail"

    # Run command: sudo find /usr/bin/journalctl -exec stat -c "%n %U" {} \;
    status=$(run_check "find /usr/bin/journalctl -exec stat -c \"%n %U\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260505r958566_rule" "$status" "Ubuntu 22.04 LTS must be configured so that the "journalctl" command is owned by "root"."
}

# SV-260506r958566_rule: Ubuntu 22.04 LTS must be configured so that the "journalctl" command is group-owned by "root".
check_SV_260506r958566_rule() {
    local status="fail"

    # Run command: sudo find /usr/bin/journalctl -exec stat -c "%n %G" {} \;
    status=$(run_check "find /usr/bin/journalctl -exec stat -c \"%n %G\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260506r958566_rule" "$status" "Ubuntu 22.04 LTS must be configured so that the "journalctl" command is group-owned by "root"."
}

# SV-260507r991557_rule: Ubuntu 22.04 LTS must configure audit tools to be owned by "root".
check_SV_260507r991557_rule() {
    local status="fail"

    # Run command: stat -c "%n %U" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules
    status=$(run_check "stat -c \"%n %U\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260507r991557_rule" "$status" "Ubuntu 22.04 LTS must configure audit tools to be owned by "root"."
}

# SV-260508r958566_rule: Ubuntu 22.04 LTS must configure the "/var/log" directory to be owned by "root".
check_SV_260508r958566_rule() {
    local status="fail"

    # Run command: stat -c "%n %U" /var/log
    status=$(run_check "stat -c \"%n %U\" /var/log")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260508r958566_rule" "$status" "Ubuntu 22.04 LTS must configure the "/var/log" directory to be owned by "root"."
}

# SV-260509r958566_rule: Ubuntu 22.04 LTS must configure the "/var/log" directory to be group-owned by "syslog".
check_SV_260509r958566_rule() {
    local status="fail"

    # Run command: stat -c "%n %G" /var/log
    status=$(run_check "stat -c \"%n %G\" /var/log")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260509r958566_rule" "$status" "Ubuntu 22.04 LTS must configure the "/var/log" directory to be group-owned by "syslog"."
}

# SV-260510r958566_rule: Ubuntu 22.04 LTS must configure "/var/log/syslog" file to be owned by "syslog".
check_SV_260510r958566_rule() {
    local status="fail"

    # Run command: stat -c "%n %U" /var/log/syslog
    status=$(run_check "stat -c \"%n %U\" /var/log/syslog")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260510r958566_rule" "$status" "Ubuntu 22.04 LTS must configure "/var/log/syslog" file to be owned by "syslog"."
}

# SV-260511r958566_rule: Ubuntu 22.04 LTS must configure the "/var/log/syslog" file to be group-owned by "adm".
check_SV_260511r958566_rule() {
    local status="fail"

    # Run command: stat -c "%n %G" /var/log/syslog
    status=$(run_check "stat -c \"%n %G\" /var/log/syslog")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260511r958566_rule" "$status" "Ubuntu 22.04 LTS must configure the "/var/log/syslog" file to be group-owned by "adm"."
}

# SV-260512r958564_rule: Ubuntu 22.04 LTS must be configured so that the "journalctl" command is not accessible by unauthorized users.
check_SV_260512r958564_rule() {
    local status="fail"

    # Run command: sudo find /usr/bin/journalctl -exec stat -c "%n %a" {} \;
    status=$(run_check "find /usr/bin/journalctl -exec stat -c \"%n %a\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260512r958564_rule" "$status" "Ubuntu 22.04 LTS must be configured so that the "journalctl" command is not accessible by unauthorized users."
}

# SV-260513r958524_rule: Ubuntu 22.04 LTS must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources.
check_SV_260513r958524_rule() {
    local status="fail"

    # Run command: sudo find / -type d -perm -002 ! -perm -1000
    status=$(run_check "find / -type d -perm -002 ! -perm -1000")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260513r958524_rule" "$status" "Ubuntu 22.04 LTS must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources."
}

# SV-260514r958672_rule: Ubuntu 22.04 LTS must have an application firewall installed in order to control remote access methods.
check_SV_260514r958672_rule() {
    local status="fail"

    # Run command: dpkg -l | grep ufw
    status=$(run_check "dpkg -l | grep ufw")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260514r958672_rule" "$status" "Ubuntu 22.04 LTS must have an application firewall installed in order to control remote access methods."
}

# SV-260515r958672_rule: Ubuntu 22.04 LTS must enable and run the Uncomplicated Firewall (ufw).
check_SV_260515r958672_rule() {
    local status="fail"

    # Run command: sudo ufw status
    status=$(run_check "ufw status")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260515r958672_rule" "$status" "Ubuntu 22.04 LTS must enable and run the Uncomplicated Firewall (ufw)."
}

# SV-260516r991593_rule: Ubuntu 22.04 LTS must have an application firewall enabled.
check_SV_260516r991593_rule() {
    local status="fail"

    # Run command: systemctl status ufw.service | grep -i "active:"
    status=$(run_check "systemctl status ufw.service | grep -i \"active:\"")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260516r991593_rule" "$status" "Ubuntu 22.04 LTS must have an application firewall enabled."
}

# SV-260517r958902_rule: Ubuntu 22.04 LTS must configure the Uncomplicated Firewall (ufw) to rate-limit impacted network interfaces.
check_SV_260517r958902_rule() {
    local status="fail"

    # Run command: ss -l46ut
    status=$(run_check "ss -l46ut")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo ufw status
    status=$(run_check "ufw status")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260517r958902_rule" "$status" "Ubuntu 22.04 LTS must configure the Uncomplicated Firewall (ufw) to rate-limit impacted network interfaces."
}

# SV-260518r958480_rule: Ubuntu 22.04 LTS must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.
check_SV_260518r958480_rule() {
    local status="fail"

    # Run command: sudo ufw show raw
    status=$(run_check "ufw show raw")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260518r958480_rule" "$status" "Ubuntu 22.04 LTS must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments."
}

# SV-260519r1015004_rule: Ubuntu 22.04 LTS must, for networked systems, compare internal information system clocks at least every 24 hours with a server synchronized to one of the redundant United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DOD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).
check_SV_260519r1015004_rule() {
    local status="fail"

    # Run command: sudo grep maxpoll -ir /etc/chrony*
    status=$(run_check "grep maxpoll -ir /etc/chrony*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo grep -ir server /etc/chrony*
    status=$(run_check "grep -ir server /etc/chrony*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260519r1015004_rule" "$status" "Ubuntu 22.04 LTS must, for networked systems, compare internal information system clocks at least every 24 hours with a server synchronized to one of the redundant United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DOD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS)."
}

# SV-260520r1015005_rule: Ubuntu 22.04 LTS must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second.
check_SV_260520r1015005_rule() {
    local status="fail"

    # Run command: grep -ir makestep /etc/chrony*
    status=$(run_check "grep -ir makestep /etc/chrony*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: timedatectl | grep -Ei '(synchronized|service)'
    status=$(run_check "timedatectl | grep -Ei '(synchronized|service)'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260520r1015005_rule" "$status" "Ubuntu 22.04 LTS must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second."
}

# SV-260521r958788_rule: Ubuntu 22.04 LTS must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC).
check_SV_260521r958788_rule() {
    local status="fail"

    # Run command: timedatectl status | grep -i "time zone"
    status=$(run_check "timedatectl status | grep -i \"time zone\"")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260521r958788_rule" "$status" "Ubuntu 22.04 LTS must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC)."
}

# SV-260522r958528_rule: Ubuntu 22.04 LTS must be configured to use TCP syncookies.
check_SV_260522r958528_rule() {
    local status="fail"

    # Run command: sysctl net.ipv4.tcp_syncookies
    status=$(run_check "sysctl net.ipv4.tcp_syncookies")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo grep -ir net.ipv4.tcp_syncookies /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2> /dev/null
    status=$(run_check "grep -ir net.ipv4.tcp_syncookies /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2> /dev/null")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260522r958528_rule" "$status" "Ubuntu 22.04 LTS must be configured to use TCP syncookies."
}

# SV-260523r958908_rule: Ubuntu 22.04 LTS must have SSH installed.
check_SV_260523r958908_rule() {
    local status="fail"

    # Run command: sudo dpkg -l | grep openssh
    status=$(run_check "dpkg -l | grep openssh")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260523r958908_rule" "$status" "Ubuntu 22.04 LTS must have SSH installed."
}

# SV-260524r958908_rule: Ubuntu 22.04 LTS must use SSH to protect the confidentiality and integrity of transmitted information.
check_SV_260524r958908_rule() {
    local status="fail"

    # Run command: sudo systemctl is-enabled ssh
    status=$(run_check "systemctl is-enabled ssh")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo systemctl is-active ssh
    status=$(run_check "systemctl is-active ssh")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260524r958908_rule" "$status" "Ubuntu 22.04 LTS must use SSH to protect the confidentiality and integrity of transmitted information."
}

# SV-260525r958390_rule: Ubuntu 22.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting any local or remote connection to the system.
check_SV_260525r958390_rule() {
    local status="fail"

    # Run command: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'banner'
    status=$(run_check "/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH 'banner'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: cat /etc/issue.net
    status=$(run_check "cat /etc/issue.net")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260525r958390_rule" "$status" "Ubuntu 22.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting any local or remote connection to the system."
}

# SV-260526r991591_rule: Ubuntu 22.04 LTS must not allow unattended or automatic login via SSH.
check_SV_260526r991591_rule() {
    local status="fail"

    # Run command: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iEH '(permit(.*?)(passwords|environment))'
    status=$(run_check "/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iEH '(permit(.*?)(passwords|environment))'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260526r991591_rule" "$status" "Ubuntu 22.04 LTS must not allow unattended or automatic login via SSH."
}

# SV-260527r986275_rule: Ubuntu 22.04 LTS must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive.
check_SV_260527r986275_rule() {
    local status="fail"

    # Run command: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'clientalivecountmax'
    status=$(run_check "/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH 'clientalivecountmax'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260527r986275_rule" "$status" "Ubuntu 22.04 LTS must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive."
}

# SV-260528r970703_rule: Ubuntu 22.04 LTS must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive.
check_SV_260528r970703_rule() {
    local status="fail"

    # Run command: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'clientaliveinterval'
    status=$(run_check "/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH 'clientaliveinterval'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260528r970703_rule" "$status" "Ubuntu 22.04 LTS must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive."
}

# SV-260529r991589_rule: Ubuntu 22.04 LTS must be configured so that remote X connections are disabled, unless to fulfill documented and validated mission requirements.
check_SV_260529r991589_rule() {
    local status="fail"

    # Run command: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'x11forwarding'
    status=$(run_check "/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH 'x11forwarding'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260529r991589_rule" "$status" "Ubuntu 22.04 LTS must be configured so that remote X connections are disabled, unless to fulfill documented and validated mission requirements."
}

# SV-260530r991589_rule: Ubuntu 22.04 LTS SSH daemon must prevent remote hosts from connecting to the proxy display.
check_SV_260530r991589_rule() {
    local status="fail"

    # Run command: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'x11uselocalhost'
    status=$(run_check "/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH 'x11uselocalhost'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260530r991589_rule" "$status" "Ubuntu 22.04 LTS SSH daemon must prevent remote hosts from connecting to the proxy display."
}

# SV-260531r958408_rule: Ubuntu 22.04 LTS must configure the SSH daemon to use FIPS 140-3-approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.
check_SV_260531r958408_rule() {
    local status="fail"

    # Run command: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'ciphers'
    status=$(run_check "/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH 'ciphers'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260531r958408_rule" "$status" "Ubuntu 22.04 LTS must configure the SSH daemon to use FIPS 140-3-approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission."
}

# SV-260532r991554_rule: Ubuntu 22.04 LTS must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-3-approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.
check_SV_260532r991554_rule() {
    local status="fail"

    # Run command: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'macs'
    status=$(run_check "/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH 'macs'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260532r991554_rule" "$status" "Ubuntu 22.04 LTS must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-3-approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to information during transmission."
}

# SV-260533r958408_rule: Ubuntu 22.04 LTS SSH server must be configured to use only FIPS-validated key exchange algorithms.
check_SV_260533r958408_rule() {
    local status="fail"

    # Run command: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'kexalgorithms'
    status=$(run_check "/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH 'kexalgorithms'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260533r958408_rule" "$status" "Ubuntu 22.04 LTS SSH server must be configured to use only FIPS-validated key exchange algorithms."
}

# SV-260534r958510_rule: Ubuntu 22.04 LTS must use strong authenticators in establishing nonlocal maintenance and diagnostic sessions.
check_SV_260534r958510_rule() {
    local status="fail"

    # Run command: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'usepam'
    status=$(run_check "/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH 'usepam'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260534r958510_rule" "$status" "Ubuntu 22.04 LTS must use strong authenticators in establishing nonlocal maintenance and diagnostic sessions."
}

# SV-260535r958390_rule: Ubuntu 22.04 LTS must enable the graphical user logon banner to display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon.
check_SV_260535r958390_rule() {
    local status="fail"

    # Run command: grep -i banner-message-enable /etc/gdm3/greeter.dconf-defaults
    status=$(run_check "grep -i banner-message-enable /etc/gdm3/greeter.dconf-defaults")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260535r958390_rule" "$status" "Ubuntu 22.04 LTS must enable the graphical user logon banner to display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon."
}

# SV-260536r958390_rule: Ubuntu 22.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon.
check_SV_260536r958390_rule() {
    local status="fail"

    # Run command: grep -i banner-message-text /etc/gdm3/greeter.dconf-defaults
    status=$(run_check "grep -i banner-message-text /etc/gdm3/greeter.dconf-defaults")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260536r958390_rule" "$status" "Ubuntu 22.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon."
}

# SV-260537r958400_rule: Ubuntu 22.04 LTS must retain a user's session lock until that user reestablishes access using established identification and authentication procedures.
check_SV_260537r958400_rule() {
    local status="fail"

    # Run command: sudo gsettings get org.gnome.desktop.screensaver lock-enabled
    status=$(run_check "gsettings get org.gnome.desktop.screensaver lock-enabled")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260537r958400_rule" "$status" "Ubuntu 22.04 LTS must retain a user's session lock until that user reestablishes access using established identification and authentication procedures."
}

# SV-260538r958402_rule: Ubuntu 22.04 LTS must initiate a graphical session lock after 15 minutes of inactivity.
check_SV_260538r958402_rule() {
    local status="fail"

    # Run command: gsettings get org.gnome.desktop.screensaver lock-enabled
    status=$(run_check "gsettings get org.gnome.desktop.screensaver lock-enabled")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: gsettings get org.gnome.desktop.screensaver lock-delay
    status=$(run_check "gsettings get org.gnome.desktop.screensaver lock-delay")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: gsettings get org.gnome.desktop.session idle-delay
    status=$(run_check "gsettings get org.gnome.desktop.session idle-delay")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260538r958402_rule" "$status" "Ubuntu 22.04 LTS must initiate a graphical session lock after 15 minutes of inactivity."
}

# SV-260539r991589_rule: Ubuntu 22.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence if a graphical user interface is installed.
check_SV_260539r991589_rule() {
    local status="fail"

    # Run command: gsettings get org.gnome.settings-daemon.plugins.media-keys logout
    status=$(run_check "gsettings get org.gnome.settings-daemon.plugins.media-keys logout")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260539r991589_rule" "$status" "Ubuntu 22.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence if a graphical user interface is installed."
}

# SV-260540r986276_rule: Ubuntu 22.04 LTS must disable automatic mounting of Universal Serial Bus (USB) mass storage driver.
check_SV_260540r986276_rule() {
    local status="fail"

    # Run command: grep usb-storage /etc/modprobe.d/* | grep "/bin/false"
    status=$(run_check "grep usb-storage /etc/modprobe.d/* | grep \"/bin/false\"")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: grep usb-storage /etc/modprobe.d/* | grep -i "blacklist"
    status=$(run_check "grep usb-storage /etc/modprobe.d/* | grep -i \"blacklist\"")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260540r986276_rule" "$status" "Ubuntu 22.04 LTS must disable automatic mounting of Universal Serial Bus (USB) mass storage driver."
}

# SV-260541r958358_rule: Ubuntu 22.04 LTS must disable all wireless network adapters.
check_SV_260541r958358_rule() {
    local status="fail"

    # Run command: cat /proc/net/wireless
    status=$(run_check "cat /proc/net/wireless")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260541r958358_rule" "$status" "Ubuntu 22.04 LTS must disable all wireless network adapters."
}

# SV-260542r1015006_rule: Ubuntu 22.04 LTS must prevent direct login into the root account.
check_SV_260542r1015006_rule() {
    local status="fail"

    # Run command: sudo passwd -S root
    status=$(run_check "passwd -S root")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260542r1015006_rule" "$status" "Ubuntu 22.04 LTS must prevent direct login into the root account."
}

# SV-260543r958482_rule: Ubuntu 22.04 LTS must uniquely identify interactive users.
check_SV_260543r958482_rule() {
    local status="fail"

    # Run command: awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd
    status=$(run_check "awk -F \":\" 'list[$3]++{print $1, $3}' /etc/passwd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260543r958482_rule" "$status" "Ubuntu 22.04 LTS must uniquely identify interactive users."
}

# SV-260545r1015007_rule: Ubuntu 22.04 LTS must enforce 24 hours/one day as the minimum password lifetime. Passwords for new users must have a 24 hours/one day minimum password lifetime restriction.
check_SV_260545r1015007_rule() {
    local status="fail"

    # Run command: grep -i pass_min_days /etc/login.defs
    status=$(run_check "grep -i pass_min_days /etc/login.defs")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260545r1015007_rule" "$status" "Ubuntu 22.04 LTS must enforce 24 hours/one day as the minimum password lifetime. Passwords for new users must have a 24 hours/one day minimum password lifetime restriction."
}

# SV-260546r1015008_rule: Ubuntu 22.04 LTS must enforce a 60-day maximum password lifetime restriction. Passwords for new users must have a 60-day maximum password lifetime restriction.
check_SV_260546r1015008_rule() {
    local status="fail"

    # Run command: grep -i pass_max_days /etc/login.defs
    status=$(run_check "grep -i pass_max_days /etc/login.defs")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260546r1015008_rule" "$status" "Ubuntu 22.04 LTS must enforce a 60-day maximum password lifetime restriction. Passwords for new users must have a 60-day maximum password lifetime restriction."
}

# SV-260547r1015009_rule: Ubuntu 22.04 LTS must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.
check_SV_260547r1015009_rule() {
    local status="fail"

    # Run command: grep INACTIVE /etc/default/useradd
    status=$(run_check "grep INACTIVE /etc/default/useradd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260547r1015009_rule" "$status" "Ubuntu 22.04 LTS must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity."
}

# SV-260548r958364_rule: Ubuntu 22.04 LTS must automatically expire temporary accounts within 72 hours.
check_SV_260548r958364_rule() {
    local status="fail"

    # Run command: sudo chage -l <temporary_account_name> | grep -E '(Password|Account) expires'
    status=$(run_check "chage -l <temporary_account_name> | grep -E '(Password|Account) expires'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260548r958364_rule" "$status" "Ubuntu 22.04 LTS must automatically expire temporary accounts within 72 hours."
}

# SV-260549r958388_rule: Ubuntu 22.04 LTS must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts have been made.
check_SV_260549r958388_rule() {
    local status="fail"

    # Run command: grep faillock /etc/pam.d/common-auth
    status=$(run_check "grep faillock /etc/pam.d/common-auth")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo grep -Ew 'silent|audit|deny|fail_interval|unlock_time' /etc/security/faillock.conf
    status=$(run_check "grep -Ew 'silent|audit|deny|fail_interval|unlock_time' /etc/security/faillock.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260549r958388_rule" "$status" "Ubuntu 22.04 LTS must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts have been made."
}

# SV-260550r991588_rule: Ubuntu 22.04 LTS must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.
check_SV_260550r991588_rule() {
    local status="fail"

    # Run command: grep pam_faildelay /etc/pam.d/common-auth
    status=$(run_check "grep pam_faildelay /etc/pam.d/common-auth")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260550r991588_rule" "$status" "Ubuntu 22.04 LTS must enforce a delay of at least four seconds between logon prompts following a failed logon attempt."
}

# SV-260551r991589_rule: Ubuntu 22.04 LTS must display the date and time of the last successful account logon upon logon.
check_SV_260551r991589_rule() {
    local status="fail"

    # Run command: grep pam_lastlog /etc/pam.d/login
    status=$(run_check "grep pam_lastlog /etc/pam.d/login")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260551r991589_rule" "$status" "Ubuntu 22.04 LTS must display the date and time of the last successful account logon upon logon."
}

# SV-260552r958398_rule: Ubuntu 22.04 LTS must limit the number of concurrent sessions to ten for all accounts and/or account types.
check_SV_260552r958398_rule() {
    local status="fail"

    # Run command: sudo grep -r -s '^[^#].*maxlogins' /etc/security/limits.conf /etc/security/limits.d/*.conf
    status=$(run_check "grep -r -s '^[^#].*maxlogins' /etc/security/limits.conf /etc/security/limits.d/*.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260552r958398_rule" "$status" "Ubuntu 22.04 LTS must limit the number of concurrent sessions to ten for all accounts and/or account types."
}

# SV-260553r1015010_rule: Ubuntu 22.04 LTS must allow users to directly initiate a session lock for all connection types.
check_SV_260553r1015010_rule() {
    local status="fail"

    # Run command: dpkg -l | grep vlock
    status=$(run_check "dpkg -l | grep vlock")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260553r1015010_rule" "$status" "Ubuntu 22.04 LTS must allow users to directly initiate a session lock for all connection types."
}

# SV-260554r958636_rule: Ubuntu 22.04 LTS must automatically exit interactive command shell user sessions after 15 minutes of inactivity.
check_SV_260554r958636_rule() {
    local status="fail"

    # Run command: sudo grep -E "\bTMOUT=[0-9]+" /etc/bash.bashrc /etc/profile.d/*
    status=$(run_check "grep -E \"\bTMOUT=[0-9]+\" /etc/bash.bashrc /etc/profile.d/*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260554r958636_rule" "$status" "Ubuntu 22.04 LTS must automatically exit interactive command shell user sessions after 15 minutes of inactivity."
}

# SV-260555r991590_rule: Ubuntu 22.04 LTS default filesystem permissions must be defined in such a way that all authenticated users can read and modify only their own files.
check_SV_260555r991590_rule() {
    local status="fail"

    # Run command: grep -i '^\s*umask' /etc/login.defs
    status=$(run_check "grep -i '^\s*umask' /etc/login.defs")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260555r991590_rule" "$status" "Ubuntu 22.04 LTS default filesystem permissions must be defined in such a way that all authenticated users can read and modify only their own files."
}

# SV-260556r958702_rule: Ubuntu 22.04 LTS must have the "apparmor" package installed.
check_SV_260556r958702_rule() {
    local status="fail"

    # Run command: dpkg -l | grep apparmor
    status=$(run_check "dpkg -l | grep apparmor")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260556r958702_rule" "$status" "Ubuntu 22.04 LTS must have the "apparmor" package installed."
}

# SV-260557r958804_rule: Ubuntu 22.04 LTS must be configured to use AppArmor.
check_SV_260557r958804_rule() {
    local status="fail"

    # Run command: systemctl is-enabled apparmor.service
    status=$(run_check "systemctl is-enabled apparmor.service")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: systemctl is-active apparmor.service
    status=$(run_check "systemctl is-active apparmor.service")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo apparmor_status | grep -i profile
    status=$(run_check "apparmor_status | grep -i profile")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260557r958804_rule" "$status" "Ubuntu 22.04 LTS must be configured to use AppArmor."
}

# SV-260558r1015011_rule: Ubuntu 22.04 LTS must require users to reauthenticate for privilege escalation or when changing roles.
check_SV_260558r1015011_rule() {
    local status="fail"

    # Run command: sudo grep -Ei '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*
    status=$(run_check "grep -Ei '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260558r1015011_rule" "$status" "Ubuntu 22.04 LTS must require users to reauthenticate for privilege escalation or when changing roles."
}

# SV-260559r958518_rule: Ubuntu 22.04 LTS must ensure only users who need access to security functions are part of sudo group.
check_SV_260559r958518_rule() {
    local status="fail"

    # Run command: grep sudo /etc/group
    status=$(run_check "grep /etc/group")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260559r958518_rule" "$status" "Ubuntu 22.04 LTS must ensure only users who need access to security functions are part of sudo group."
}

# SV-260560r1015012_rule: Ubuntu 22.04 LTS must enforce password complexity by requiring at least one uppercase character be used.
check_SV_260560r1015012_rule() {
    local status="fail"

    # Run command: grep -i ucredit /etc/security/pwquality.conf
    status=$(run_check "grep -i ucredit /etc/security/pwquality.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260560r1015012_rule" "$status" "Ubuntu 22.04 LTS must enforce password complexity by requiring at least one uppercase character be used."
}

# SV-260561r1015013_rule: Ubuntu 22.04 LTS must enforce password complexity by requiring at least one lowercase character be used.
check_SV_260561r1015013_rule() {
    local status="fail"

    # Run command: grep -i lcredit /etc/security/pwquality.conf
    status=$(run_check "grep -i lcredit /etc/security/pwquality.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260561r1015013_rule" "$status" "Ubuntu 22.04 LTS must enforce password complexity by requiring at least one lowercase character be used."
}

# SV-260562r1015014_rule: Ubuntu 22.04 LTS must enforce password complexity by requiring that at least one numeric character be used.
check_SV_260562r1015014_rule() {
    local status="fail"

    # Run command: grep -i dcredit /etc/security/pwquality.conf
    status=$(run_check "grep -i dcredit /etc/security/pwquality.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260562r1015014_rule" "$status" "Ubuntu 22.04 LTS must enforce password complexity by requiring that at least one numeric character be used."
}

# SV-260563r1015015_rule: Ubuntu 22.04 LTS must enforce password complexity by requiring that at least one special character be used.
check_SV_260563r1015015_rule() {
    local status="fail"

    # Run command: grep -i ocredit /etc/security/pwquality.conf
    status=$(run_check "grep -i ocredit /etc/security/pwquality.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260563r1015015_rule" "$status" "Ubuntu 22.04 LTS must enforce password complexity by requiring that at least one special character be used."
}

# SV-260564r991587_rule: Ubuntu 22.04 LTS must prevent the use of dictionary words for passwords.
check_SV_260564r991587_rule() {
    local status="fail"

    # Run command: grep -i dictcheck /etc/security/pwquality.conf
    status=$(run_check "grep -i dictcheck /etc/security/pwquality.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260564r991587_rule" "$status" "Ubuntu 22.04 LTS must prevent the use of dictionary words for passwords."
}

# SV-260565r1015016_rule: Ubuntu 22.04 LTS must enforce a minimum 15-character password length.
check_SV_260565r1015016_rule() {
    local status="fail"

    # Run command: grep -i minlen /etc/security/pwquality.conf
    status=$(run_check "grep -i minlen /etc/security/pwquality.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260565r1015016_rule" "$status" "Ubuntu 22.04 LTS must enforce a minimum 15-character password length."
}

# SV-260566r1015017_rule: Ubuntu 22.04 LTS must require the change of at least eight characters when passwords are changed.
check_SV_260566r1015017_rule() {
    local status="fail"

    # Run command: grep -i difok /etc/security/pwquality.conf
    status=$(run_check "grep -i difok /etc/security/pwquality.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260566r1015017_rule" "$status" "Ubuntu 22.04 LTS must require the change of at least eight characters when passwords are changed."
}

# SV-260567r991587_rule: Ubuntu 22.04 LTS must be configured so that when passwords are changed or new passwords are established, pwquality must be used.
check_SV_260567r991587_rule() {
    local status="fail"

    # Run command: grep -i enforcing /etc/security/pwquality.conf
    status=$(run_check "grep -i enforcing /etc/security/pwquality.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: cat /etc/pam.d/common-password | grep requisite | grep pam_pwquality
    status=$(run_check "cat /etc/pam.d/common-password | grep requisite | grep pam_pwquality")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260567r991587_rule" "$status" "Ubuntu 22.04 LTS must be configured so that when passwords are changed or new passwords are established, pwquality must be used."
}

# SV-260569r1015018_rule: Ubuntu 22.04 LTS must store only encrypted representations of passwords.
check_SV_260569r1015018_rule() {
    local status="fail"

    # Run command: grep pam_unix.so /etc/pam.d/common-password
    status=$(run_check "grep pam_unix.so /etc/pam.d/common-password")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260569r1015018_rule" "$status" "Ubuntu 22.04 LTS must store only encrypted representations of passwords."
}

# SV-260570r991589_rule: Ubuntu 22.04 LTS must not allow accounts configured with blank or null passwords.
check_SV_260570r991589_rule() {
    local status="fail"

    # Run command: grep nullok /etc/pam.d/common-password
    status=$(run_check "grep nullok /etc/pam.d/common-password")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260570r991589_rule" "$status" "Ubuntu 22.04 LTS must not allow accounts configured with blank or null passwords."
}

# SV-260571r991589_rule: Ubuntu 22.04 LTS must not have accounts configured with blank or null passwords.
check_SV_260571r991589_rule() {
    local status="fail"

    # Run command: sudo awk -F: '!$2 {print $1}' /etc/shadow
    status=$(run_check "awk -F: '!$2 {print $1}' /etc/shadow")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260571r991589_rule" "$status" "Ubuntu 22.04 LTS must not have accounts configured with blank or null passwords."
}

# SV-260572r971535_rule: Ubuntu 22.04 LTS must encrypt all stored passwords with a FIPS 140-3-approved cryptographic hashing algorithm.
check_SV_260572r971535_rule() {
    local status="fail"

    # Run command: grep -i '^\s*encrypt_method' /etc/login.defs
    status=$(run_check "grep -i '^\s*encrypt_method' /etc/login.defs")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260572r971535_rule" "$status" "Ubuntu 22.04 LTS must encrypt all stored passwords with a FIPS 140-3-approved cryptographic hashing algorithm."
}

# SV-260573r1015019_rule: Ubuntu 22.04 LTS must implement multifactor authentication for remote access to privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access.
check_SV_260573r1015019_rule() {
    local status="fail"

    # Run command: dpkg -l | grep libpam-pkcs11
    status=$(run_check "dpkg -l | grep libpam-pkcs11")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260573r1015019_rule" "$status" "Ubuntu 22.04 LTS must implement multifactor authentication for remote access to privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access."
}

# SV-260574r958816_rule: Ubuntu 22.04 LTS must accept personal identity verification (PIV) credentials.
check_SV_260574r958816_rule() {
    local status="fail"

    # Run command: dpkg -l | grep opensc-pkcs11
    status=$(run_check "dpkg -l | grep opensc-pkcs11")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260574r958816_rule" "$status" "Ubuntu 22.04 LTS must accept personal identity verification (PIV) credentials."
}

# SV-260575r1015020_rule: Ubuntu 22.04 LTS must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts.
check_SV_260575r1015020_rule() {
    local status="fail"

    # Run command: grep -i pam_pkcs11.so /etc/pam.d/common-auth
    status=$(run_check "grep -i pam_pkcs11.so /etc/pam.d/common-auth")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'pubkeyauthentication'
    status=$(run_check "/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH 'pubkeyauthentication'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260575r1015020_rule" "$status" "Ubuntu 22.04 LTS must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts."
}

# SV-260576r958818_rule: Ubuntu 22.04 LTS must electronically verify personal identity verification (PIV) credentials.
check_SV_260576r958818_rule() {
    local status="fail"

    # Run command: sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ocsp_on
    status=$(run_check "grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ocsp_on")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260576r958818_rule" "$status" "Ubuntu 22.04 LTS must electronically verify personal identity verification (PIV) credentials."
}

# SV-260577r986294_rule: Ubuntu 22.04 LTS, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.
check_SV_260577r986294_rule() {
    local status="fail"

    # Run command: sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ca
    status=$(run_check "grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ca")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260577r986294_rule" "$status" "Ubuntu 22.04 LTS, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor."
}

# SV-260578r1015021_rule: Ubuntu 22.04 LTS for PKI-based authentication, must implement a local cache of revocation data in case of the inability to access revocation information via the network.
check_SV_260578r1015021_rule() {
    local status="fail"

    # Run command: grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep  -E -- 'crl_auto|crl_offline'
    status=$(run_check "grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep  -E -- 'crl_auto|crl_offline'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260578r1015021_rule" "$status" "Ubuntu 22.04 LTS for PKI-based authentication, must implement a local cache of revocation data in case of the inability to access revocation information via the network."
}

# SV-260579r958452_rule: Ubuntu 22.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication.
check_SV_260579r958452_rule() {
    local status="fail"

    # Run command: grep -i use_mappers /etc/pam_pkcs11/pam_pkcs11.conf
    status=$(run_check "grep -i use_mappers /etc/pam_pkcs11/pam_pkcs11.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260579r958452_rule" "$status" "Ubuntu 22.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication."
}

# SV-260580r958868_rule: Ubuntu 22.04 LTS must use DOD PKI-established certificate authorities for verification of the establishment of protected sessions.
check_SV_260580r958868_rule() {
    local status="fail"

    # Run command: ls /etc/ssl/certs | grep -i DOD
    status=$(run_check "ls /etc/ssl/certs | grep -i DOD")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: ls /etc/ssl/certs
    status=$(run_check "ls /etc/ssl/certs")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260580r958868_rule" "$status" "Ubuntu 22.04 LTS must use DOD PKI-established certificate authorities for verification of the establishment of protected sessions."
}

# SV-260581r958828_rule: Ubuntu 22.04 LTS must be configured such that Pluggable Authentication Module (PAM) prohibits the use of cached authentications after one day.
check_SV_260581r958828_rule() {
    local status="fail"

    # Run command: sudo grep -i '^\s*offline_credentials_expiration' /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf
    status=$(run_check "grep -i '^\s*offline_credentials_expiration' /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260581r958828_rule" "$status" "Ubuntu 22.04 LTS must be configured such that Pluggable Authentication Module (PAM) prohibits the use of cached authentications after one day."
}

# SV-260582r958944_rule: Ubuntu 22.04 LTS must use a file integrity tool to verify correct operation of all security functions.
check_SV_260582r958944_rule() {
    local status="fail"

    # Run command: dpkg -l | grep aide
    status=$(run_check "dpkg -l | grep aide")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260582r958944_rule" "$status" "Ubuntu 22.04 LTS must use a file integrity tool to verify correct operation of all security functions."
}

# SV-260583r958944_rule: Ubuntu 22.04 LTS must configure AIDE to perform file integrity checking on the file system.
check_SV_260583r958944_rule() {
    local status="fail"

    # Run command: sudo aide -c /etc/aide/aide.conf --check
    status=$(run_check "aide -c /etc/aide/aide.conf --check")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260583r958944_rule" "$status" "Ubuntu 22.04 LTS must configure AIDE to perform file integrity checking on the file system."
}

# SV-260584r958794_rule: Ubuntu 22.04 LTS must notify designated personnel if baseline configurations are changed in an unauthorized manner. The file integrity tool must notify the system administrator when changes to the baseline configuration or anomalies in the operation of any security functions are discovered.
check_SV_260584r958794_rule() {
    local status="fail"

    # Run command: grep -i '^\s*silentreports' /etc/default/aide
    status=$(run_check "grep -i '^\s*silentreports' /etc/default/aide")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260584r958794_rule" "$status" "Ubuntu 22.04 LTS must notify designated personnel if baseline configurations are changed in an unauthorized manner. The file integrity tool must notify the system administrator when changes to the baseline configuration or anomalies in the operation of any security functions are discovered."
}

# SV-260585r958946_rule: Ubuntu 22.04 LTS must be configured so that the script that runs each 30 days or less to check file integrity is the default.
check_SV_260585r958946_rule() {
    local status="fail"

    # Run command: cd /tmp; apt download aide-common
    status=$(run_check "cd /tmp; apt download aide-common")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: dpkg-deb --fsys-tarfile /tmp/aide-common_*.deb | tar -xO ./usr/share/aide/config/cron.daily/aide | sha1sum
    status=$(run_check "dpkg-deb --fsys-tarfile /tmp/aide-common_*.deb | tar -xO ./usr/share/aide/config/cron.daily/aide | sha1sum")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sha1sum /etc/cron.{daily,monthly}/aide 2>/dev/null
    status=$(run_check "sha1sum /etc/cron.{daily,monthly}/aide 2>/dev/null")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260585r958946_rule" "$status" "Ubuntu 22.04 LTS must be configured so that the script that runs each 30 days or less to check file integrity is the default."
}

# SV-260586r991567_rule: Ubuntu 22.04 LTS must use cryptographic mechanisms to protect the integrity of audit tools.
check_SV_260586r991567_rule() {
    local status="fail"

    # Run command: grep -E '(\/sbin\/(audit|au))' /etc/aide/aide.conf
    status=$(run_check "grep -E '(\/sbin\/(audit|au))' /etc/aide/aide.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260586r991567_rule" "$status" "Ubuntu 22.04 LTS must use cryptographic mechanisms to protect the integrity of audit tools."
}

# SV-260587r959008_rule: Ubuntu 22.04 LTS must have a crontab script running weekly to offload audit events of standalone systems.
check_SV_260587r959008_rule() {
    local status="fail"

    # Run command: ls /etc/cron.weekly
    status=$(run_check "ls /etc/cron.weekly")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260587r959008_rule" "$status" "Ubuntu 22.04 LTS must have a crontab script running weekly to offload audit events of standalone systems."
}

# SV-260588r991562_rule: Ubuntu 22.04 LTS must be configured to preserve log records from failure events.
check_SV_260588r991562_rule() {
    local status="fail"

    # Run command: dpkg -l | grep rsyslog
    status=$(run_check "dpkg -l | grep rsyslog")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: systemctl is-enabled rsyslog.service
    status=$(run_check "systemctl is-enabled rsyslog.service")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: systemctl is-active rsyslog.service
    status=$(run_check "systemctl is-active rsyslog.service")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260588r991562_rule" "$status" "Ubuntu 22.04 LTS must be configured to preserve log records from failure events."
}

# SV-260589r958406_rule: Ubuntu 22.04 LTS must monitor remote access methods.
check_SV_260589r958406_rule() {
    local status="fail"

    # Run command: grep -Er '^(auth\.\*,authpriv\.\*|daemon\.\*)' /etc/rsyslog.*
    status=$(run_check "grep -Er '^(auth\.\*,authpriv\.\*|daemon\.\*)' /etc/rsyslog.*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260589r958406_rule" "$status" "Ubuntu 22.04 LTS must monitor remote access methods."
}

# SV-260590r1015022_rule: Ubuntu 22.04 LTS must have the "auditd" package installed.
check_SV_260590r1015022_rule() {
    local status="fail"

    # Run command: dpkg -l | grep auditd
    status=$(run_check "dpkg -l | grep auditd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260590r1015022_rule" "$status" "Ubuntu 22.04 LTS must have the "auditd" package installed."
}

# SV-260591r1015023_rule: Ubuntu 22.04 LTS must produce audit records and reports containing information to establish when, where, what type, the source, and the outcome for all DOD-defined auditable events and actions in near real time.
check_SV_260591r1015023_rule() {
    local status="fail"

    # Run command: systemctl is-enabled auditd.service
    status=$(run_check "systemctl is-enabled auditd.service")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: systemctl is-active auditd.service
    status=$(run_check "systemctl is-active auditd.service")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260591r1015023_rule" "$status" "Ubuntu 22.04 LTS must produce audit records and reports containing information to establish when, where, what type, the source, and the outcome for all DOD-defined auditable events and actions in near real time."
}

# SV-260592r958754_rule: Ubuntu 22.04 LTS audit event multiplexor must be configured to offload audit logs onto a different system from the system being audited.
check_SV_260592r958754_rule() {
    local status="fail"

    # Run command: dpkg -l | grep audispd-plugins
    status=$(run_check "dpkg -l | grep audispd-plugins")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo grep -i active /etc/audit/plugins.d/au-remote.conf
    status=$(run_check "grep -i active /etc/audit/plugins.d/au-remote.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo grep -i remote_server /etc/audit/audisp-remote.conf
    status=$(run_check "grep -i remote_server /etc/audit/audisp-remote.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260592r958754_rule" "$status" "Ubuntu 22.04 LTS audit event multiplexor must be configured to offload audit logs onto a different system from the system being audited."
}

# SV-260593r958424_rule: Ubuntu 22.04 LTS must alert the information system security officer (ISSO) and system administrator (SA) in the event of an audit processing failure.
check_SV_260593r958424_rule() {
    local status="fail"

    # Run command: sudo grep -i action_mail_acct /etc/audit/auditd.conf
    status=$(run_check "grep -i action_mail_acct /etc/audit/auditd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260593r958424_rule" "$status" "Ubuntu 22.04 LTS must alert the information system security officer (ISSO) and system administrator (SA) in the event of an audit processing failure."
}

# SV-260594r958426_rule: Ubuntu 22.04 LTS must shut down by default upon audit failure.
check_SV_260594r958426_rule() {
    local status="fail"

    # Run command: sudo grep -i disk_full_action /etc/audit/auditd.conf
    status=$(run_check "grep -i disk_full_action /etc/audit/auditd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260594r958426_rule" "$status" "Ubuntu 22.04 LTS must shut down by default upon audit failure."
}

# SV-260595r958752_rule: Ubuntu 22.04 LTS must allocate audit record storage capacity to store at least one weeks' worth of audit records, when audit records are not immediately sent to a central audit record storage facility.
check_SV_260595r958752_rule() {
    local status="fail"

    # Run command: sudo grep -i log_file /etc/audit/auditd.conf
    status=$(run_check "grep -i log_file /etc/audit/auditd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo df -h /var/log/audit/
    status=$(run_check "df -h /var/log/audit/")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo du -sh <audit_partition>
    status=$(run_check "du -sh <audit_partition>")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260595r958752_rule" "$status" "Ubuntu 22.04 LTS must allocate audit record storage capacity to store at least one weeks' worth of audit records, when audit records are not immediately sent to a central audit record storage facility."
}

# SV-260596r971542_rule: Ubuntu 22.04 LTS must immediately notify the system administrator (SA) and information system security officer (ISSO) when the audit record storage volume reaches 25 percent remaining of the allocated capacity.
check_SV_260596r971542_rule() {
    local status="fail"

    # Run command: sudo grep -i space_left /etc/audit/auditd.conf
    status=$(run_check "grep -i space_left /etc/audit/auditd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260596r971542_rule" "$status" "Ubuntu 22.04 LTS must immediately notify the system administrator (SA) and information system security officer (ISSO) when the audit record storage volume reaches 25 percent remaining of the allocated capacity."
}

# SV-260597r958434_rule: Ubuntu 22.04 LTS must be configured so that audit log files are not read- or write-accessible by unauthorized users.
check_SV_260597r958434_rule() {
    local status="fail"

    # Run command: sudo grep -iw log_file /etc/audit/auditd.conf
    status=$(run_check "grep -iw log_file /etc/audit/auditd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo stat -c "%n %a" /var/log/audit/*
    status=$(run_check "stat -c \"%n %a\" /var/log/audit/*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260597r958434_rule" "$status" "Ubuntu 22.04 LTS must be configured so that audit log files are not read- or write-accessible by unauthorized users."
}

# SV-260598r958434_rule: Ubuntu 22.04 LTS must be configured to permit only authorized users ownership of the audit log files.
check_SV_260598r958434_rule() {
    local status="fail"

    # Run command: sudo grep -iw log_file /etc/audit/auditd.conf
    status=$(run_check "grep -iw log_file /etc/audit/auditd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo stat -c "%n %U" /var/log/audit/*
    status=$(run_check "stat -c \"%n %U\" /var/log/audit/*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260598r958434_rule" "$status" "Ubuntu 22.04 LTS must be configured to permit only authorized users ownership of the audit log files."
}

# SV-260599r958434_rule: Ubuntu 22.04 LTS must permit only authorized groups ownership of the audit log files.
check_SV_260599r958434_rule() {
    local status="fail"

    # Run command: sudo grep -iw log_group /etc/audit/auditd.conf
    status=$(run_check "grep -iw log_group /etc/audit/auditd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260599r958434_rule" "$status" "Ubuntu 22.04 LTS must permit only authorized groups ownership of the audit log files."
}

# SV-260600r958438_rule: Ubuntu 22.04 LTS must be configured so that the audit log directory is not write-accessible by unauthorized users.
check_SV_260600r958438_rule() {
    local status="fail"

    # Run command: sudo grep -iw log_file /etc/audit/auditd.conf
    status=$(run_check "grep -iw log_file /etc/audit/auditd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo stat -c "%n %a" /var/log/audit
    status=$(run_check "stat -c \"%n %a\" /var/log/audit")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260600r958438_rule" "$status" "Ubuntu 22.04 LTS must be configured so that the audit log directory is not write-accessible by unauthorized users."
}

# SV-260601r958444_rule: Ubuntu 22.04 LTS must be configured so that audit configuration files are not write-accessible by unauthorized users.
check_SV_260601r958444_rule() {
    local status="fail"

    # Run command: sudo ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print $1, $9}'
    status=$(run_check "ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print $1, $9}'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260601r958444_rule" "$status" "Ubuntu 22.04 LTS must be configured so that audit configuration files are not write-accessible by unauthorized users."
}

# SV-260602r958444_rule: Ubuntu 22.04 LTS must permit only authorized accounts to own the audit configuration files.
check_SV_260602r958444_rule() {
    local status="fail"

    # Run command: sudo ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print $3, $9}'
    status=$(run_check "ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print $3, $9}'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260602r958444_rule" "$status" "Ubuntu 22.04 LTS must permit only authorized accounts to own the audit configuration files."
}

# SV-260603r958444_rule: Ubuntu 22.04 LTS must permit only authorized groups to own the audit configuration files.
check_SV_260603r958444_rule() {
    local status="fail"

    # Run command: sudo ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print $4, $9}'
    status=$(run_check "ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print $4, $9}'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260603r958444_rule" "$status" "Ubuntu 22.04 LTS must permit only authorized groups to own the audit configuration files."
}

# SV-260604r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the apparmor_parser command.
check_SV_260604r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep apparmor_parser
    status=$(run_check "auditctl -l | grep apparmor_parser")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260604r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the apparmor_parser command."
}

# SV-260605r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chacl command.
check_SV_260605r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep chacl
    status=$(run_check "auditctl -l | grep chacl")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260605r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chacl command."
}

# SV-260606r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chage command.
check_SV_260606r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep -w chage
    status=$(run_check "auditctl -l | grep -w chage")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260606r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chage command."
}

# SV-260607r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chcon command.
check_SV_260607r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep chcon
    status=$(run_check "auditctl -l | grep chcon")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260607r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chcon command."
}

# SV-260608r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chfn command.
check_SV_260608r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep /usr/bin/chfn
    status=$(run_check "auditctl -l | grep /usr/bin/chfn")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260608r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chfn command."
}

# SV-260609r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chsh command.
check_SV_260609r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep chsh
    status=$(run_check "auditctl -l | grep chsh")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260609r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chsh command."
}

# SV-260610r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the crontab command.
check_SV_260610r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep -w crontab
    status=$(run_check "auditctl -l | grep -w crontab")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260610r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the crontab command."
}

# SV-260611r991586_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use the fdisk command.
check_SV_260611r991586_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep fdisk
    status=$(run_check "auditctl -l | grep fdisk")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260611r991586_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use the fdisk command."
}

# SV-260612r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the gpasswd command.
check_SV_260612r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep -w gpasswd
    status=$(run_check "auditctl -l | grep -w gpasswd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260612r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the gpasswd command."
}

# SV-260613r991586_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use the kmod command.
check_SV_260613r991586_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep kmod
    status=$(run_check "auditctl -l | grep kmod")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260613r991586_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use the kmod command."
}

# SV-260614r991586_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use modprobe command.
check_SV_260614r991586_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep /sbin/modprobe
    status=$(run_check "auditctl -l | grep /sbin/modprobe")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260614r991586_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use modprobe command."
}

# SV-260615r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the mount command.
check_SV_260615r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep /usr/bin/mount
    status=$(run_check "auditctl -l | grep /usr/bin/mount")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260615r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the mount command."
}

# SV-260616r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the newgrp command.
check_SV_260616r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep newgrp
    status=$(run_check "auditctl -l | grep newgrp")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260616r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the newgrp command."
}

# SV-260617r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the pam_timestamp_check command.
check_SV_260617r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep -w pam_timestamp_check
    status=$(run_check "auditctl -l | grep -w pam_timestamp_check")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260617r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the pam_timestamp_check command."
}

# SV-260618r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the passwd command.
check_SV_260618r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep -w passwd
    status=$(run_check "auditctl -l | grep -w passwd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260618r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the passwd command."
}

# SV-260619r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the setfacl command.
check_SV_260619r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep setfacl
    status=$(run_check "auditctl -l | grep setfacl")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260619r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the setfacl command."
}

# SV-260620r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the ssh-agent command.
check_SV_260620r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep /usr/bin/ssh-agent
    status=$(run_check "auditctl -l | grep /usr/bin/ssh-agent")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260620r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the ssh-agent command."
}

# SV-260621r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the ssh-keysign command.
check_SV_260621r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep ssh-keysign
    status=$(run_check "auditctl -l | grep ssh-keysign")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260621r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the ssh-keysign command."
}

# SV-260622r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the su command.
check_SV_260622r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep /bin/su
    status=$(run_check "auditctl -l | grep /bin/su")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260622r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the su command."
}

# SV-260623r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the sudo command.
check_SV_260623r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep /usr/bin/sudo
    status=$(run_check "auditctl -l | grep /usr/bin/sudo")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260623r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the sudo command."
}

# SV-260624r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the sudoedit command.
check_SV_260624r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep /usr/bin/sudoedit
    status=$(run_check "auditctl -l | grep /usr/bin/sudoedit")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260624r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the sudoedit command."
}

# SV-260625r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the umount command.
check_SV_260625r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep /usr/bin/umount
    status=$(run_check "auditctl -l | grep /usr/bin/umount")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260625r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the umount command."
}

# SV-260626r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the unix_update command.
check_SV_260626r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep -w unix_update
    status=$(run_check "auditctl -l | grep -w unix_update")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260626r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the unix_update command."
}

# SV-260627r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the usermod command.
check_SV_260627r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep -w usermod
    status=$(run_check "auditctl -l | grep -w usermod")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260627r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the usermod command."
}

# SV-260628r958368_rule: Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group.
check_SV_260628r958368_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep group
    status=$(run_check "auditctl -l | grep group")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260628r958368_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group."
}

# SV-260629r958368_rule: Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow.
check_SV_260629r958368_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep gshadow
    status=$(run_check "auditctl -l | grep gshadow")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260629r958368_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow."
}

# SV-260630r958368_rule: Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd.
check_SV_260630r958368_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep opasswd
    status=$(run_check "auditctl -l | grep opasswd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260630r958368_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd."
}

# SV-260631r958368_rule: Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd.
check_SV_260631r958368_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep passwd
    status=$(run_check "auditctl -l | grep passwd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260631r958368_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd."
}

# SV-260632r958368_rule: Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow.
check_SV_260632r958368_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep shadow
    status=$(run_check "auditctl -l | grep shadow")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260632r958368_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow."
}

# SV-260633r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chmod, fchmod, and fchmodat system calls.
check_SV_260633r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep chmod
    status=$(run_check "auditctl -l | grep chmod")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260633r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chmod, fchmod, and fchmodat system calls."
}

# SV-260634r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chown, fchown, fchownat, and lchown system calls.
check_SV_260634r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep chown
    status=$(run_check "auditctl -l | grep chown")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260634r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chown, fchown, fchownat, and lchown system calls."
}

# SV-260635r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls.
check_SV_260635r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep 'open\|truncate\|creat'
    status=$(run_check "auditctl -l | grep 'open\|truncate\|creat'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260635r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls."
}

# SV-260636r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the delete_module system call.
check_SV_260636r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep -w delete_module
    status=$(run_check "auditctl -l | grep -w delete_module")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260636r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the delete_module system call."
}

# SV-260637r958446_rule: Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the init_module and finit_module system calls.
check_SV_260637r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep init_module
    status=$(run_check "auditctl -l | grep init_module")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260637r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the init_module and finit_module system calls."
}

# SV-260638r958446_rule: Ubuntu 22.04 LTS must generate audit records for any use of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls.
check_SV_260638r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep xattr
    status=$(run_check "auditctl -l | grep xattr")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260638r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for any use of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls."
}

# SV-260639r991577_rule: Ubuntu 22.04 LTS must generate audit records for any successful/unsuccessful use of unlink, unlinkat, rename, renameat, and rmdir system calls.
check_SV_260639r991577_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep 'unlink\|rename\|rmdir'
    status=$(run_check "auditctl -l | grep 'unlink\|rename\|rmdir'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260639r991577_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for any successful/unsuccessful use of unlink, unlinkat, rename, renameat, and rmdir system calls."
}

# SV-260640r991589_rule: Ubuntu 22.04 LTS must generate audit records for all events that affect the systemd journal files.
check_SV_260640r991589_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep journal
    status=$(run_check "auditctl -l | grep journal")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260640r991589_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for all events that affect the systemd journal files."
}

# SV-260641r991581_rule: Ubuntu 22.04 LTS must generate audit records for the /var/log/btmp file.
check_SV_260641r991581_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep '/var/log/btmp'
    status=$(run_check "auditctl -l | grep '/var/log/btmp'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260641r991581_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for the /var/log/btmp file."
}

# SV-260642r991581_rule: Ubuntu 22.04 LTS must generate audit records for the /var/log/wtmp file.
check_SV_260642r991581_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep '/var/log/wtmp'
    status=$(run_check "auditctl -l | grep '/var/log/wtmp'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260642r991581_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for the /var/log/wtmp file."
}

# SV-260643r991581_rule: Ubuntu 22.04 LTS must generate audit records for the /var/run/utmp file.
check_SV_260643r991581_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep '/var/run/utmp'
    status=$(run_check "auditctl -l | grep '/var/run/utmp'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260643r991581_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for the /var/run/utmp file."
}

# SV-260644r958446_rule: Ubuntu 22.04 LTS must generate audit records for the use and modification of faillog file.
check_SV_260644r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep faillog
    status=$(run_check "auditctl -l | grep faillog")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260644r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for the use and modification of faillog file."
}

# SV-260645r958446_rule: Ubuntu 22.04 LTS must generate audit records for the use and modification of the lastlog file.
check_SV_260645r958446_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep lastlog
    status=$(run_check "auditctl -l | grep lastlog")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260645r958446_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for the use and modification of the lastlog file."
}

# SV-260646r991575_rule: Ubuntu 22.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers file occur.
check_SV_260646r991575_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep sudoers
    status=$(run_check "auditctl -l | grep sudoers")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260646r991575_rule" "$status" "Ubuntu 22.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers file occur."
}

# SV-260647r991575_rule: Ubuntu 22.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers.d directory occur.
check_SV_260647r991575_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep sudoers.d
    status=$(run_check "auditctl -l | grep sudoers.d")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260647r991575_rule" "$status" "Ubuntu 22.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers.d directory occur."
}

# SV-260648r958730_rule: Ubuntu 22.04 LTS must prevent all software from executing at higher privilege levels than users executing the software and the audit system must be configured to audit the execution of privileged functions.
check_SV_260648r958730_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep execve
    status=$(run_check "auditctl -l | grep execve")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260648r958730_rule" "$status" "Ubuntu 22.04 LTS must prevent all software from executing at higher privilege levels than users executing the software and the audit system must be configured to audit the execution of privileged functions."
}

# SV-260649r986298_rule: Ubuntu 22.04 LTS must generate audit records for privileged activities, nonlocal maintenance, diagnostic sessions and other system-level access.
check_SV_260649r986298_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep sudo.log
    status=$(run_check "auditctl -l | grep sudo.log")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260649r986298_rule" "$status" "Ubuntu 22.04 LTS must generate audit records for privileged activities, nonlocal maintenance, diagnostic sessions and other system-level access."
}

# SV-260650r987791_rule: Ubuntu 22.04 LTS must implement NIST FIPS-validated cryptography to protect classified information and for the following: To provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.
check_SV_260650r987791_rule() {
    local status="fail"

    # Run command: grep -i 1 /proc/sys/crypto/fips_enabled
    status=$(run_check "grep -i 1 /proc/sys/crypto/fips_enabled")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-260650r987791_rule" "$status" "Ubuntu 22.04 LTS must implement NIST FIPS-validated cryptography to protect classified information and for the following: To provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards."
}

# Execute all checks
check_SV_260469r991589_rule
check_SV_260470r958472_rule
check_SV_260471r991555_rule
check_SV_260472r958524_rule
check_SV_260473r958550_rule
check_SV_260474r958928_rule
check_SV_260475r958928_rule
check_SV_260476r1015003_rule
check_SV_260477r958936_rule
check_SV_260478r991587_rule
check_SV_260479r991589_rule
check_SV_260480r991589_rule
check_SV_260481r991589_rule
check_SV_260482r958478_rule
check_SV_260483r987796_rule
check_SV_260484r958552_rule
check_SV_260485r991559_rule
check_SV_260486r991560_rule
check_SV_260487r991560_rule
check_SV_260488r958566_rule
check_SV_260489r958564_rule
check_SV_260490r1014781_rule
check_SV_260491r958566_rule
check_SV_260492r991557_rule
check_SV_260493r991559_rule
check_SV_260494r991559_rule
check_SV_260495r991560_rule
check_SV_260496r991560_rule
check_SV_260497r991560_rule
check_SV_260498r991560_rule
check_SV_260499r991560_rule
check_SV_260500r991560_rule
check_SV_260501r958566_rule
check_SV_260502r958566_rule
check_SV_260503r958566_rule
check_SV_260504r958566_rule
check_SV_260505r958566_rule
check_SV_260506r958566_rule
check_SV_260507r991557_rule
check_SV_260508r958566_rule
check_SV_260509r958566_rule
check_SV_260510r958566_rule
check_SV_260511r958566_rule
check_SV_260512r958564_rule
check_SV_260513r958524_rule
check_SV_260514r958672_rule
check_SV_260515r958672_rule
check_SV_260516r991593_rule
check_SV_260517r958902_rule
check_SV_260518r958480_rule
check_SV_260519r1015004_rule
check_SV_260520r1015005_rule
check_SV_260521r958788_rule
check_SV_260522r958528_rule
check_SV_260523r958908_rule
check_SV_260524r958908_rule
check_SV_260525r958390_rule
check_SV_260526r991591_rule
check_SV_260527r986275_rule
check_SV_260528r970703_rule
check_SV_260529r991589_rule
check_SV_260530r991589_rule
check_SV_260531r958408_rule
check_SV_260532r991554_rule
check_SV_260533r958408_rule
check_SV_260534r958510_rule
check_SV_260535r958390_rule
check_SV_260536r958390_rule
check_SV_260537r958400_rule
check_SV_260538r958402_rule
check_SV_260539r991589_rule
check_SV_260540r986276_rule
check_SV_260541r958358_rule
check_SV_260542r1015006_rule
check_SV_260543r958482_rule
check_SV_260545r1015007_rule
check_SV_260546r1015008_rule
check_SV_260547r1015009_rule
check_SV_260548r958364_rule
check_SV_260549r958388_rule
check_SV_260550r991588_rule
check_SV_260551r991589_rule
check_SV_260552r958398_rule
check_SV_260553r1015010_rule
check_SV_260554r958636_rule
check_SV_260555r991590_rule
check_SV_260556r958702_rule
check_SV_260557r958804_rule
check_SV_260558r1015011_rule
check_SV_260559r958518_rule
check_SV_260560r1015012_rule
check_SV_260561r1015013_rule
check_SV_260562r1015014_rule
check_SV_260563r1015015_rule
check_SV_260564r991587_rule
check_SV_260565r1015016_rule
check_SV_260566r1015017_rule
check_SV_260567r991587_rule
check_SV_260569r1015018_rule
check_SV_260570r991589_rule
check_SV_260571r991589_rule
check_SV_260572r971535_rule
check_SV_260573r1015019_rule
check_SV_260574r958816_rule
check_SV_260575r1015020_rule
check_SV_260576r958818_rule
check_SV_260577r986294_rule
check_SV_260578r1015021_rule
check_SV_260579r958452_rule
check_SV_260580r958868_rule
check_SV_260581r958828_rule
check_SV_260582r958944_rule
check_SV_260583r958944_rule
check_SV_260584r958794_rule
check_SV_260585r958946_rule
check_SV_260586r991567_rule
check_SV_260587r959008_rule
check_SV_260588r991562_rule
check_SV_260589r958406_rule
check_SV_260590r1015022_rule
check_SV_260591r1015023_rule
check_SV_260592r958754_rule
check_SV_260593r958424_rule
check_SV_260594r958426_rule
check_SV_260595r958752_rule
check_SV_260596r971542_rule
check_SV_260597r958434_rule
check_SV_260598r958434_rule
check_SV_260599r958434_rule
check_SV_260600r958438_rule
check_SV_260601r958444_rule
check_SV_260602r958444_rule
check_SV_260603r958444_rule
check_SV_260604r958446_rule
check_SV_260605r958446_rule
check_SV_260606r958446_rule
check_SV_260607r958446_rule
check_SV_260608r958446_rule
check_SV_260609r958446_rule
check_SV_260610r958446_rule
check_SV_260611r991586_rule
check_SV_260612r958446_rule
check_SV_260613r991586_rule
check_SV_260614r991586_rule
check_SV_260615r958446_rule
check_SV_260616r958446_rule
check_SV_260617r958446_rule
check_SV_260618r958446_rule
check_SV_260619r958446_rule
check_SV_260620r958446_rule
check_SV_260621r958446_rule
check_SV_260622r958446_rule
check_SV_260623r958446_rule
check_SV_260624r958446_rule
check_SV_260625r958446_rule
check_SV_260626r958446_rule
check_SV_260627r958446_rule
check_SV_260628r958368_rule
check_SV_260629r958368_rule
check_SV_260630r958368_rule
check_SV_260631r958368_rule
check_SV_260632r958368_rule
check_SV_260633r958446_rule
check_SV_260634r958446_rule
check_SV_260635r958446_rule
check_SV_260636r958446_rule
check_SV_260637r958446_rule
check_SV_260638r958446_rule
check_SV_260639r991577_rule
check_SV_260640r991589_rule
check_SV_260641r991581_rule
check_SV_260642r991581_rule
check_SV_260643r991581_rule
check_SV_260644r958446_rule
check_SV_260645r958446_rule
check_SV_260646r991575_rule
check_SV_260647r991575_rule
check_SV_260648r958730_rule
check_SV_260649r986298_rule
check_SV_260650r987791_rule

# Generate final report
generate_report
