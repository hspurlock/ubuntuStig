#!/bin/bash

# STIG Compliance Check Script
# Generated from XCCDF file: U_CAN_Ubuntu_24-04_LTS_STIG_V1R1_Manual-xccdf.xml

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

# SV-270645r1068357_rule: Ubuntu 24.04 LTS must not have the "systemd-timesyncd" package installed.
check_SV_270645r1068357_rule() {
    local status="fail"

    # Run command: dpkg -l | grep systemd-timesyncd
    status=$(run_check "dpkg -l | grep systemd-timesyncd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270645r1068357_rule" "$status" "Ubuntu 24.04 LTS must not have the "systemd-timesyncd" package installed."
}

# SV-270646r1068358_rule: Ubuntu 24.04 LTS must not have the "ntp" package installed.
check_SV_270646r1068358_rule() {
    local status="fail"

    # Run command: dpkg -l | grep ntp
    status=$(run_check "dpkg -l | grep ntp")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270646r1068358_rule" "$status" "Ubuntu 24.04 LTS must not have the "ntp" package installed."
}

# SV-270647r1066430_rule: Ubuntu 24.04 LTS must not have the telnet package installed.
check_SV_270647r1066430_rule() {
    local status="fail"

    # Run command: dpkg -l | grep telnetd
    status=$(run_check "dpkg -l | grep telnetd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270647r1066430_rule" "$status" "Ubuntu 24.04 LTS must not have the telnet package installed."
}

# SV-270648r1066433_rule: Ubuntu 24.04 LTS must not have the rsh-server package installed.
check_SV_270648r1066433_rule() {
    local status="fail"

    # Run command: dpkg -l | grep rsh-server
    status=$(run_check "dpkg -l | grep rsh-server")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270648r1066433_rule" "$status" "Ubuntu 24.04 LTS must not have the rsh-server package installed."
}

# SV-270649r1067136_rule: Ubuntu 24.04 LTS must use a file integrity tool to verify correct operation of all security functions.
check_SV_270649r1067136_rule() {
    local status="fail"

    # Run command: dpkg -l | grep aide
    status=$(run_check "dpkg -l | grep aide")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270649r1067136_rule" "$status" "Ubuntu 24.04 LTS must use a file integrity tool to verify correct operation of all security functions."
}

# SV-270650r1066439_rule: Ubuntu 24.04 LTS must configure AIDE to preform file integrity checking on the file system.
check_SV_270650r1066439_rule() {
    local status="fail"

    # Run command: sudo aide -c /etc/aide/aide.conf --check
    status=$(run_check "aide -c /etc/aide/aide.conf --check")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270650r1066439_rule" "$status" "Ubuntu 24.04 LTS must configure AIDE to preform file integrity checking on the file system."
}

# SV-270651r1068395_rule: Ubuntu 24.04 LTS must be configured so that the script which runs each 30 days or less to check file integrity is the default one.
check_SV_270651r1068395_rule() {
    local status="fail"

    # Run command: sudo sha256sum /etc/aide/aide.conf
    status=$(run_check "sha256sum /etc/aide/aide.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: cd /tmp; apt download aide-common
    status=$(run_check "cd /tmp; apt download aide-common")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo dpkg-deb --fsys-tarfile /tmp/aide-common_0.18.6-2build2_all.deb | tar -xO ./usr/share/aide/config/aide/aide.conf | sha256sum
    status=$(run_check "dpkg-deb --fsys-tarfile /tmp/aide-common_0.18.6-2build2_all.deb | tar -xO ./usr/share/aide/config/aide/aide.conf | sha256sum")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: grep -r aide /etc/cron* /etc/crontab
    status=$(run_check "grep -r aide /etc/cron* /etc/crontab")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo systemctl list-timers | grep aide
    status=$(run_check "systemctl list-timers | grep aide")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo systemctl cat dailyaidecheck.timer
    status=$(run_check "systemctl cat dailyaidecheck.timer")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo systemctl cat dailyaidecheck.service
    status=$(run_check "systemctl cat dailyaidecheck.service")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270651r1068395_rule" "$status" "Ubuntu 24.04 LTS must be configured so that the script which runs each 30 days or less to check file integrity is the default one."
}

# SV-270652r1067138_rule: Ubuntu 24.04 LTS must notify designated personnel if baseline configurations are changed in an unauthorized manner. The file integrity tool must notify the system administrator (SA) when changes to the baseline configuration or anomalies in the operation of any security functions are discovered.
check_SV_270652r1067138_rule() {
    local status="fail"

    # Run command: grep SILENTREPORTS /etc/default/aide
    status=$(run_check "grep SILENTREPORTS /etc/default/aide")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270652r1067138_rule" "$status" "Ubuntu 24.04 LTS must notify designated personnel if baseline configurations are changed in an unauthorized manner. The file integrity tool must notify the system administrator (SA) when changes to the baseline configuration or anomalies in the operation of any security functions are discovered."
}

# SV-270653r1067141_rule: Ubuntu 24.04 LTS must be configured to preserve log records from failure events.
check_SV_270653r1067141_rule() {
    local status="fail"

    # Run command: dpkg -l | grep rsyslog
    status=$(run_check "dpkg -l | grep rsyslog")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: systemctl is-enabled rsyslog
    status=$(run_check "systemctl is-enabled rsyslog")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: systemctl is-active rsyslog
    status=$(run_check "systemctl is-active rsyslog")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270653r1067141_rule" "$status" "Ubuntu 24.04 LTS must be configured to preserve log records from failure events."
}

# SV-270654r1067143_rule: Ubuntu 24.04 LTS must have an application firewall installed in order to control remote access methods.
check_SV_270654r1067143_rule() {
    local status="fail"

    # Run command: dpkg -l | grep ufw
    status=$(run_check "dpkg -l | grep ufw")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270654r1067143_rule" "$status" "Ubuntu 24.04 LTS must have an application firewall installed in order to control remote access methods."
}

# SV-270655r1067145_rule: Ubuntu 24.04 LTS must enable and run the Uncomplicated Firewall (ufw).
check_SV_270655r1067145_rule() {
    local status="fail"

    # Run command: sudo ufw status
    status=$(run_check "ufw status")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270655r1067145_rule" "$status" "Ubuntu 24.04 LTS must enable and run the Uncomplicated Firewall (ufw)."
}

# SV-270656r1067148_rule: Ubuntu 24.04 LTS must have the "auditd" package installed.
check_SV_270656r1067148_rule() {
    local status="fail"

    # Run command: dpkg -l | grep auditd
    status=$(run_check "dpkg -l | grep auditd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270656r1067148_rule" "$status" "Ubuntu 24.04 LTS must have the "auditd" package installed."
}

# SV-270657r1066460_rule: Ubuntu 24.04 LTS must produce audit records and reports containing information to establish when, where, what type, the source, and the outcome for all DOD-defined auditable events and actions in near real time.
check_SV_270657r1066460_rule() {
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
    log_result "SV-270657r1066460_rule" "$status" "Ubuntu 24.04 LTS must produce audit records and reports containing information to establish when, where, what type, the source, and the outcome for all DOD-defined auditable events and actions in near real time."
}

# SV-270658r1067151_rule: Ubuntu 24.04 LTS audit event multiplexor must be configured to offload audit logs onto a different system or storage media from the system being audited.
check_SV_270658r1067151_rule() {
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

    # Run command: sudo grep -i ^remote_server /etc/audit/audisp-remote.conf
    status=$(run_check "grep -i ^remote_server /etc/audit/audisp-remote.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270658r1067151_rule" "$status" "Ubuntu 24.04 LTS audit event multiplexor must be configured to offload audit logs onto a different system or storage media from the system being audited."
}

# SV-270659r1066466_rule: Ubuntu 24.04 LTS must have AppArmor installed.
check_SV_270659r1066466_rule() {
    local status="fail"

    # Run command: dpkg -l | grep apparmor
    status=$(run_check "dpkg -l | grep apparmor")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270659r1066466_rule" "$status" "Ubuntu 24.04 LTS must have AppArmor installed."
}

# SV-270660r1066469_rule: Ubuntu 24.04 LTS must be configured to use AppArmor.
check_SV_270660r1066469_rule() {
    local status="fail"

    # Run command: systemctl is-active apparmor.service
    status=$(run_check "systemctl is-active apparmor.service")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: systemctl is-enabled apparmor.service
    status=$(run_check "systemctl is-enabled apparmor.service")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270660r1066469_rule" "$status" "Ubuntu 24.04 LTS must be configured to use AppArmor."
}

# SV-270661r1067175_rule: Ubuntu 24.04 LTS must have the "libpam-pwquality" package installed.
check_SV_270661r1067175_rule() {
    local status="fail"

    # Run command: dpkg -l | grep libpam-pwquality
    status=$(run_check "dpkg -l | grep libpam-pwquality")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270661r1067175_rule" "$status" "Ubuntu 24.04 LTS must have the "libpam-pwquality" package installed."
}

# SV-270662r1067156_rule: Ubuntu 24.04 LTS must have the "SSSD" package installed.
check_SV_270662r1067156_rule() {
    local status="fail"

    # Run command: dpkg -l | grep sssd
    status=$(run_check "dpkg -l | grep sssd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: dpkg -l | grep libpam-sss
    status=$(run_check "dpkg -l | grep libpam-sss")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: dpkg -l | grep libnss-sss
    status=$(run_check "dpkg -l | grep libnss-sss")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270662r1067156_rule" "$status" "Ubuntu 24.04 LTS must have the "SSSD" package installed."
}

# SV-270663r1066478_rule: Ubuntu 24.04 LTS must use the "SSSD" package for multifactor authentication services.
check_SV_270663r1066478_rule() {
    local status="fail"

    # Run command: sudo systemctl is-enabled sssd
    status=$(run_check "systemctl is-enabled sssd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo systemctl is-active sssd
    status=$(run_check "systemctl is-active sssd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270663r1066478_rule" "$status" "Ubuntu 24.04 LTS must use the "SSSD" package for multifactor authentication services."
}

# SV-270664r1068359_rule: Ubuntu 24.04 LTS must have the "chrony" package installed.
check_SV_270664r1068359_rule() {
    local status="fail"

    # Run command: dpkg -l | grep chrony
    status=$(run_check "dpkg -l | grep chrony")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270664r1068359_rule" "$status" "Ubuntu 24.04 LTS must have the "chrony" package installed."
}

# SV-270665r1067133_rule: Ubuntu 24.04 LTS must have SSH installed.
check_SV_270665r1067133_rule() {
    local status="fail"

    # Run command: dpkg -l | grep openssh
    status=$(run_check "dpkg -l | grep openssh")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270665r1067133_rule" "$status" "Ubuntu 24.04 LTS must have SSH installed."
}

# SV-270666r1066487_rule: Ubuntu 24.04 LTS must use SSH to protect the confidentiality and integrity of transmitted information.
check_SV_270666r1066487_rule() {
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
    log_result "SV-270666r1066487_rule" "$status" "Ubuntu 24.04 LTS must use SSH to protect the confidentiality and integrity of transmitted information."
}

# SV-270667r1067107_rule: Ubuntu 24.04 LTS must configure the SSH daemon to use FIPS 140-3 approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.
check_SV_270667r1067107_rule() {
    local status="fail"

    # Run command: sudo grep -r 'Ciphers' /etc/ssh/sshd_config*
    status=$(run_check "grep -r 'Ciphers' /etc/ssh/sshd_config*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270667r1067107_rule" "$status" "Ubuntu 24.04 LTS must configure the SSH daemon to use FIPS 140-3 approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission."
}

# SV-270668r1067110_rule: Ubuntu 24.04 LTS must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-3 approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.
check_SV_270668r1067110_rule() {
    local status="fail"

    # Run command: grep -irs macs /etc/ssh/sshd_config*
    status=$(run_check "grep -irs macs /etc/ssh/sshd_config*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270668r1067110_rule" "$status" "Ubuntu 24.04 LTS must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-3 approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to information during transmission."
}

# SV-270669r1067112_rule: Ubuntu 24.04 LTS SSH server must be configured to use only FIPS 140-3 validated key exchange algorithms.
check_SV_270669r1067112_rule() {
    local status="fail"

    # Run command: sudo grep -ir kexalgorithms /etc/ssh/sshd_config*
    status=$(run_check "grep -ir kexalgorithms /etc/ssh/sshd_config*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270669r1067112_rule" "$status" "Ubuntu 24.04 LTS SSH server must be configured to use only FIPS 140-3 validated key exchange algorithms."
}

# SV-270670r1067115_rule: Ubuntu 24.04 LTS must configure the SSH client to use FIPS 140-3 approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.
check_SV_270670r1067115_rule() {
    local status="fail"

    # Run command: sudo grep -r 'Ciphers' /etc/ssh/ssh_config*
    status=$(run_check "grep -r 'Ciphers' /etc/ssh/ssh_config*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270670r1067115_rule" "$status" "Ubuntu 24.04 LTS must configure the SSH client to use FIPS 140-3 approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission."
}

# SV-270671r1067118_rule: Ubuntu 24.04 LTS SSH client must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms.
check_SV_270671r1067118_rule() {
    local status="fail"

    # Run command: sudo grep -ir macs /etc/ssh/ssh_config*
    status=$(run_check "grep -ir macs /etc/ssh/ssh_config*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270671r1067118_rule" "$status" "Ubuntu 24.04 LTS SSH client must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms."
}

# SV-270672r1067161_rule: Ubuntu 24.04 LTS must accept Personal Identity Verification (PIV) credentials.
check_SV_270672r1067161_rule() {
    local status="fail"

    # Run command: dpkg -l | grep opensc-pkcs11
    status=$(run_check "dpkg -l | grep opensc-pkcs11")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270672r1067161_rule" "$status" "Ubuntu 24.04 LTS must accept Personal Identity Verification (PIV) credentials."
}

# SV-270673r1067164_rule: Ubuntu 24.04 LTS must accept Personal Identity Verification (PIV) credentials managed through the Privileged Access Management (PAM)  framework.
check_SV_270673r1067164_rule() {
    local status="fail"

    # Run command: dpkg -l | grep libpam-pkcs11
    status=$(run_check "dpkg -l | grep libpam-pkcs11")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270673r1067164_rule" "$status" "Ubuntu 24.04 LTS must accept Personal Identity Verification (PIV) credentials managed through the Privileged Access Management (PAM)  framework."
}

# SV-270674r1067167_rule: Ubuntu 24.04 LTS must allow users to directly initiate a session lock for all connection types.
check_SV_270674r1067167_rule() {
    local status="fail"

    # Run command: dpkg -l | grep vlock
    status=$(run_check "dpkg -l | grep vlock")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270674r1067167_rule" "$status" "Ubuntu 24.04 LTS must allow users to directly initiate a session lock for all connection types."
}

# SV-270675r1066514_rule: Ubuntu 24.04 LTS when booted must require authentication upon booting into single-user and maintenance modes.
check_SV_270675r1066514_rule() {
    local status="fail"

    # Run command: sudo grep -i password /boot/grub/grub.cfg
    status=$(run_check "grep -i password /boot/grub/grub.cfg")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270675r1066514_rule" "$status" "Ubuntu 24.04 LTS when booted must require authentication upon booting into single-user and maintenance modes."
}

# SV-270676r1068360_rule: Ubuntu 24.04 LTS must initiate session audits at system startup.
check_SV_270676r1068360_rule() {
    local status="fail"

    # Run command: sudo grep "^\s*linux" /boot/grub/grub.cfg
    status=$(run_check "grep \"^\s*linux\" /boot/grub/grub.cfg")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270676r1068360_rule" "$status" "Ubuntu 24.04 LTS must initiate session audits at system startup."
}

# SV-270677r1066520_rule: Ubuntu 24.04 LTS must limit the number of concurrent sessions to 10 for all accounts and/or account types.
check_SV_270677r1066520_rule() {
    local status="fail"

    # Run command: grep maxlogins /etc/security/limits.conf | grep -v '^* hard maxlogins'
    status=$(run_check "grep maxlogins /etc/security/limits.conf | grep -v '^* hard maxlogins'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270677r1066520_rule" "$status" "Ubuntu 24.04 LTS must limit the number of concurrent sessions to 10 for all accounts and/or account types."
}

# SV-270678r1066523_rule: Ubuntu 24.04 LTS must initiate a graphical session lock after 10 minutes of inactivity.
check_SV_270678r1066523_rule() {
    local status="fail"

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
    log_result "SV-270678r1066523_rule" "$status" "Ubuntu 24.04 LTS must initiate a graphical session lock after 10 minutes of inactivity."
}

# SV-270679r1066526_rule: Ubuntu 24.04 LTS must retain a user's session lock until the user reestablishes access using established identification and authentication procedures.
check_SV_270679r1066526_rule() {
    local status="fail"

    # Run command: sudo gsettings get org.gnome.desktop.screensaver lock-enabled
    status=$(run_check "gsettings get org.gnome.desktop.screensaver lock-enabled")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270679r1066526_rule" "$status" "Ubuntu 24.04 LTS must retain a user's session lock until the user reestablishes access using established identification and authentication procedures."
}

# SV-270680r1066529_rule: Ubuntu 24.04 LTS must automatically terminate a user session after inactivity timeouts have expired.
check_SV_270680r1066529_rule() {
    local status="fail"

    # Run command: sudo grep -E "\bTMOUT=[0-9]+" /etc/bash.bashrc /etc/profile.d/*
    status=$(run_check "grep -E \"\bTMOUT=[0-9]+\" /etc/bash.bashrc /etc/profile.d/*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270680r1066529_rule" "$status" "Ubuntu 24.04 LTS must automatically terminate a user session after inactivity timeouts have expired."
}

# SV-270681r1066532_rule: Ubuntu 24.04 LTS must monitor remote access methods.
check_SV_270681r1066532_rule() {
    local status="fail"

    # Run command: grep -E -r '^(auth,authpriv\.\*|daemon\.\*)' /etc/rsyslog.*
    status=$(run_check "grep -E -r '^(auth,authpriv\.\*|daemon\.\*)' /etc/rsyslog.*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270681r1066532_rule" "$status" "Ubuntu 24.04 LTS must monitor remote access methods."
}

# SV-270682r1066535_rule: Ubuntu 24.04 LTS must automatically remove or disable emergency accounts after 72 hours.
check_SV_270682r1066535_rule() {
    local status="fail"

    # Run command: sudo chage -l <temporary_account_name> | grep -i "account expires"
    status=$(run_check "chage -l <temporary_account_name> | grep -i \"account expires\"")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270682r1066535_rule" "$status" "Ubuntu 24.04 LTS must automatically remove or disable emergency accounts after 72 hours."
}

# SV-270683r1066538_rule: Ubuntu 24.04 LTS must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.
check_SV_270683r1066538_rule() {
    local status="fail"

    # Run command: grep INACTIVE /etc/default/useradd
    status=$(run_check "grep INACTIVE /etc/default/useradd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270683r1066538_rule" "$status" "Ubuntu 24.04 LTS must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity."
}

# SV-270684r1066541_rule: Ubuntu 24.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd.
check_SV_270684r1066541_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep passwd
    status=$(run_check "auditctl -l | grep passwd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270684r1066541_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd."
}

# SV-270685r1066544_rule: Ubuntu 24.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group.
check_SV_270685r1066544_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep group
    status=$(run_check "auditctl -l | grep group")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270685r1066544_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group."
}

# SV-270686r1066547_rule: Ubuntu 24.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow.
check_SV_270686r1066547_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep shadow
    status=$(run_check "auditctl -l | grep shadow")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270686r1066547_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow."
}

# SV-270687r1066550_rule: Ubuntu 24.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow.
check_SV_270687r1066550_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep gshadow
    status=$(run_check "auditctl -l | grep gshadow")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270687r1066550_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow."
}

# SV-270688r1066553_rule: Ubuntu 24.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd.
check_SV_270688r1066553_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep opasswd
    status=$(run_check "auditctl -l | grep opasswd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270688r1066553_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd."
}

# SV-270689r1066556_rule: Ubuntu 24.04 LTS must prevent all software from executing at higher privilege levels than users executing the software and the audit system must be configured to audit the execution of privileged functions.
check_SV_270689r1066556_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep execve
    status=$(run_check "auditctl -l | grep execve")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270689r1066556_rule" "$status" "Ubuntu 24.04 LTS must prevent all software from executing at higher privilege levels than users executing the software and the audit system must be configured to audit the execution of privileged functions."
}

# SV-270690r1067126_rule: Ubuntu 24.04 LTS must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts have been made.
check_SV_270690r1067126_rule() {
    local status="fail"

    # Run command: grep faillock /etc/pam.d/common-auth
    status=$(run_check "grep faillock /etc/pam.d/common-auth")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo egrep 'silent|audit|deny|fail_interval| unlock_time' /etc/security/faillock.conf
    status=$(run_check "egrep 'silent|audit|deny|fail_interval| unlock_time' /etc/security/faillock.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270690r1067126_rule" "$status" "Ubuntu 24.04 LTS must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts have been made."
}

# SV-270691r1066562_rule: Ubuntu 24.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting access to via an SSH logon.
check_SV_270691r1066562_rule() {
    local status="fail"

    # Run command: sudo grep -ir banner /etc/ssh/sshd_config*
    status=$(run_check "grep -ir banner /etc/ssh/sshd_config*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: cat /etc/issue.net
    status=$(run_check "cat /etc/issue.net")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270691r1066562_rule" "$status" "Ubuntu 24.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting access to via an SSH logon."
}

# SV-270692r1066565_rule: Ubuntu 24.04 LTS must enable the graphical user logon banner to display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon.
check_SV_270692r1066565_rule() {
    local status="fail"

    # Run command: grep ^banner-message-enable /etc/gdm3/greeter.dconf-defaults
    status=$(run_check "grep ^banner-message-enable /etc/gdm3/greeter.dconf-defaults")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270692r1066565_rule" "$status" "Ubuntu 24.04 LTS must enable the graphical user logon banner to display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon."
}

# SV-270693r1066568_rule: Ubuntu 24.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon.
check_SV_270693r1066568_rule() {
    local status="fail"

    # Run command: grep ^banner-message-text /etc/gdm3/greeter.dconf-defaults
    status=$(run_check "grep ^banner-message-text /etc/gdm3/greeter.dconf-defaults")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270693r1066568_rule" "$status" "Ubuntu 24.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon."
}

# SV-270694r1066571_rule: Ubuntu 24.04 LTS must be configured to enforce the acknowledgement of the Standard Mandatory DOD Notice and Consent Banner for all SSH connections.
check_SV_270694r1066571_rule() {
    local status="fail"

    # Run command: less /etc/profile.d/ssh_confirm.sh
    status=$(run_check "less /etc/profile.d/ssh_confirm.sh")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270694r1066571_rule" "$status" "Ubuntu 24.04 LTS must be configured to enforce the acknowledgement of the Standard Mandatory DOD Notice and Consent Banner for all SSH connections."
}

# SV-270695r1066574_rule: Ubuntu 24.04 LTS Advance Package Tool (APT) must be configured to prevent the installation of patches, service packs, device drivers, or Ubuntu 24.04 LTS components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.
check_SV_270695r1066574_rule() {
    local status="fail"

    # Run command: grep AllowUnauthenticated /etc/apt/apt.conf.d/*
    status=$(run_check "grep AllowUnauthenticated /etc/apt/apt.conf.d/*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270695r1066574_rule" "$status" "Ubuntu 24.04 LTS Advance Package Tool (APT) must be configured to prevent the installation of patches, service packs, device drivers, or Ubuntu 24.04 LTS components without verification they have been digitally signed using a certificate that is recognized and approved by the organization."
}

# SV-270696r1066577_rule: Ubuntu 24.04 LTS library files must have mode 0755 or less permissive.
check_SV_270696r1066577_rule() {
    local status="fail"

    # Run command: sudo find /lib /lib64 /usr/lib -perm /022 -type f -exec stat -c "%n %a" '{}' \;
    status=$(run_check "find /lib /lib64 /usr/lib -perm /022 -type f -exec stat -c \"%n %a\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270696r1066577_rule" "$status" "Ubuntu 24.04 LTS library files must have mode 0755 or less permissive."
}

# SV-270697r1066580_rule: Ubuntu 24.04 LTS library files must be owned by root.
check_SV_270697r1066580_rule() {
    local status="fail"

    # Run command: sudo find /lib /usr/lib /lib64 ! -user root -type f -exec stat -c "%n %U" '{}' \;
    status=$(run_check "find /lib /usr/lib /lib64 ! -user root -type f -exec stat -c \"%n %U\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270697r1066580_rule" "$status" "Ubuntu 24.04 LTS library files must be owned by root."
}

# SV-270698r1066583_rule: Ubuntu 24.04 LTS library directories must be owned by root.
check_SV_270698r1066583_rule() {
    local status="fail"

    # Run command: sudo find /lib /usr/lib /lib64 ! -user root -type d -exec stat -c "%n %U" '{}' \;
    status=$(run_check "find /lib /usr/lib /lib64 ! -user root -type d -exec stat -c \"%n %U\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270698r1066583_rule" "$status" "Ubuntu 24.04 LTS library directories must be owned by root."
}

# SV-270699r1066586_rule: Ubuntu 24.04 LTS library files must be group-owned by root or a system account.
check_SV_270699r1066586_rule() {
    local status="fail"

    # Run command: sudo find /lib /usr/lib /lib64 ! -group root -type f -exec stat -c "%n %G" '{}' \;
    status=$(run_check "find /lib /usr/lib /lib64 ! -group root -type f -exec stat -c \"%n %G\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270699r1066586_rule" "$status" "Ubuntu 24.04 LTS library files must be group-owned by root or a system account."
}

# SV-270700r1066589_rule: Ubuntu 24.04 LTS library directories must be group-owned by root.
check_SV_270700r1066589_rule() {
    local status="fail"

    # Run command: sudo find /lib /usr/lib /lib64 ! -group root -type d -exec stat -c "%n %G" '{}' \;
    status=$(run_check "find /lib /usr/lib /lib64 ! -group root -type d -exec stat -c \"%n %G\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270700r1066589_rule" "$status" "Ubuntu 24.04 LTS library directories must be group-owned by root."
}

# SV-270701r1066592_rule: Ubuntu 24.04 LTS must have system commands set to a mode of 0755 or less permissive.
check_SV_270701r1066592_rule() {
    local status="fail"

    # Run command: sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c "%n %a" '{}' \;
    status=$(run_check "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c \"%n %a\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270701r1066592_rule" "$status" "Ubuntu 24.04 LTS must have system commands set to a mode of 0755 or less permissive."
}

# SV-270702r1066595_rule: Ubuntu 24.04 LTS must have system commands owned by root or a system account.
check_SV_270702r1066595_rule() {
    local status="fail"

    # Run command: sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c "%n %U" '{}' \;
    status=$(run_check "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c \"%n %U\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270702r1066595_rule" "$status" "Ubuntu 24.04 LTS must have system commands owned by root or a system account."
}

# SV-270703r1066598_rule: Ubuntu 24.04 LTS must have system commands group-owned by root or a system account.
check_SV_270703r1066598_rule() {
    local status="fail"

    # Run command: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin \-type f -perm -u=x -exec stat --format="%n %G" {} + |  \awk '$2 != "root" && $2 != "daemon" && $2 != "adm" && $2 != "shadow" && $2 != "mail" && $2 != "crontab" && $2 != "_ssh"'
    status=$(run_check "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin \-type f -perm -u=x -exec stat --format=\"%n %G\" {} + |  \awk '$2 != \"root\" && $2 != \"daemon\" && $2 != \"adm\" && $2 != \"shadow\" && $2 != \"mail\" && $2 != \"crontab\" && $2 != \"_ssh\"'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270703r1066598_rule" "$status" "Ubuntu 24.04 LTS must have system commands group-owned by root or a system account."
}

# SV-270704r1066601_rule: Ubuntu 24.04 LTS must prevent the use of dictionary words for passwords.
check_SV_270704r1066601_rule() {
    local status="fail"

    # Run command: grep dictcheck /etc/security/pwquality.conf
    status=$(run_check "grep dictcheck /etc/security/pwquality.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270704r1066601_rule" "$status" "Ubuntu 24.04 LTS must prevent the use of dictionary words for passwords."
}

# SV-270705r1066604_rule: Ubuntu 24.04 LTS must be configured so that when passwords are changed or new passwords are established, pwquality must be used.
check_SV_270705r1066604_rule() {
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
    log_result "SV-270705r1066604_rule" "$status" "Ubuntu 24.04 LTS must be configured so that when passwords are changed or new passwords are established, pwquality must be used."
}

# SV-270706r1068361_rule: Ubuntu 24.04 LTS must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.
check_SV_270706r1068361_rule() {
    local status="fail"

    # Run command: grep pam_faildelay /etc/pam.d/common-auth
    status=$(run_check "grep pam_faildelay /etc/pam.d/common-auth")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270706r1068361_rule" "$status" "Ubuntu 24.04 LTS must enforce a delay of at least four seconds between logon prompts following a failed logon attempt."
}

# SV-270707r1066610_rule: Ubuntu 24.04 LTS must require users to reauthenticate for privilege escalation or when changing roles.
check_SV_270707r1066610_rule() {
    local status="fail"

    # Run command: sudo egrep -i '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*
    status=$(run_check "egrep -i '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270707r1066610_rule" "$status" "Ubuntu 24.04 LTS must require users to reauthenticate for privilege escalation or when changing roles."
}

# SV-270708r1066613_rule: Ubuntu 24.04 LTS must be configured so that remote X connections are disabled, unless to fulfill documented and validated mission requirements.
check_SV_270708r1066613_rule() {
    local status="fail"

    # Run command: sudo grep -ir x11forwarding /etc/ssh/sshd_config* | grep -v "^#"
    status=$(run_check "grep -ir x11forwarding /etc/ssh/sshd_config* | grep -v \"^#\"")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270708r1066613_rule" "$status" "Ubuntu 24.04 LTS must be configured so that remote X connections are disabled, unless to fulfill documented and validated mission requirements."
}

# SV-270709r1066616_rule: Ubuntu 24.04 LTS SSH daemon must prevent remote hosts from connecting to the proxy display.
check_SV_270709r1066616_rule() {
    local status="fail"

    # Run command: sudo grep -ir x11uselocalhost /etc/ssh/sshd_config*
    status=$(run_check "grep -ir x11uselocalhost /etc/ssh/sshd_config*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270709r1066616_rule" "$status" "Ubuntu 24.04 LTS SSH daemon must prevent remote hosts from connecting to the proxy display."
}

# SV-270710r1066619_rule: Ubuntu 24.04 LTS must display the date and time of the last successful account logon upon logon.
check_SV_270710r1066619_rule() {
    local status="fail"

    # Run command: grep pam_lastlog /etc/pam.d/login
    status=$(run_check "grep pam_lastlog /etc/pam.d/login")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270710r1066619_rule" "$status" "Ubuntu 24.04 LTS must display the date and time of the last successful account logon upon logon."
}

# SV-270711r1066622_rule: Ubuntu 24.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence if a graphical user interface is installed.
check_SV_270711r1066622_rule() {
    local status="fail"

    # Run command: gsettings get org.gnome.settings-daemon.plugins.media-keys logout
    status=$(run_check "gsettings get org.gnome.settings-daemon.plugins.media-keys logout")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270711r1066622_rule" "$status" "Ubuntu 24.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence if a graphical user interface is installed."
}

# SV-270712r1068363_rule: Ubuntu 24.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence.
check_SV_270712r1068363_rule() {
    local status="fail"

    # Run command: systemctl status ctrl-alt-del.target
    status=$(run_check "systemctl status ctrl-alt-del.target")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270712r1068363_rule" "$status" "Ubuntu 24.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence."
}

# SV-270713r1066628_rule: Ubuntu 24.04 LTS must not have accounts configured with blank or null passwords.
check_SV_270713r1066628_rule() {
    local status="fail"

    # Run command: sudo awk -F: '!$2 {print $1}' /etc/shadow
    status=$(run_check "awk -F: '!$2 {print $1}' /etc/shadow")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270713r1066628_rule" "$status" "Ubuntu 24.04 LTS must not have accounts configured with blank or null passwords."
}

# SV-270714r1067119_rule: Ubuntu 24.04 LTS must not allow accounts configured in Pluggable Authentication Modules (PAM) with blank or null passwords.
check_SV_270714r1067119_rule() {
    local status="fail"

    # Run command: grep nullok /etc/pam.d/common-password
    status=$(run_check "grep nullok /etc/pam.d/common-password")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270714r1067119_rule" "$status" "Ubuntu 24.04 LTS must not allow accounts configured in Pluggable Authentication Modules (PAM) with blank or null passwords."
}

# SV-270715r1066634_rule: Ubuntu 24.04 LTS must generate audit records for all events that affect the systemd journal files.
check_SV_270715r1066634_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep journal
    status=$(run_check "auditctl -l | grep journal")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270715r1066634_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for all events that affect the systemd journal files."
}

# SV-270716r1066637_rule: Ubuntu 24.04 LTS default filesystem permissions must be defined in such a way that all authenticated users can read and modify only their own files.
check_SV_270716r1066637_rule() {
    local status="fail"

    # Run command: grep -i '^\s*umask' /etc/login.defs
    status=$(run_check "grep -i '^\s*umask' /etc/login.defs")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270716r1066637_rule" "$status" "Ubuntu 24.04 LTS default filesystem permissions must be defined in such a way that all authenticated users can read and modify only their own files."
}

# SV-270717r1067177_rule: Ubuntu 24.04 LTS must not allow unattended or automatic login via SSH.
check_SV_270717r1067177_rule() {
    local status="fail"

    # Run command: egrep -r '(Permit(.*?)(Passwords|Environment))' /etc/ssh/sshd_config
    status=$(run_check "egrep -r '(Permit(.*?)(Passwords|Environment))' /etc/ssh/sshd_config")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270717r1067177_rule" "$status" "Ubuntu 24.04 LTS must not allow unattended or automatic login via SSH."
}

# SV-270718r1067128_rule: Ubuntu 24.04 LTS must disable automatic mounting of Universal Serial Bus (USB) mass storage driver.
check_SV_270718r1067128_rule() {
    local status="fail"

    # Run command: sudo grep usb-storage /etc/modprobe.d/* | grep "/bin/true"
    status=$(run_check "grep usb-storage /etc/modprobe.d/* | grep \"/bin/true\"")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo grep usb-storage /etc/modprobe.d/* | grep -i "blacklist"
    status=$(run_check "grep usb-storage /etc/modprobe.d/* | grep -i \"blacklist\"")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270718r1067128_rule" "$status" "Ubuntu 24.04 LTS must disable automatic mounting of Universal Serial Bus (USB) mass storage driver."
}

# SV-270719r1067172_rule: Ubuntu 24.04 LTS must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL) and vulnerability assessments.
check_SV_270719r1067172_rule() {
    local status="fail"

    # Run command: sudo ufw show raw
    status=$(run_check "ufw show raw")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270719r1067172_rule" "$status" "Ubuntu 24.04 LTS must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL) and vulnerability assessments."
}

# SV-270720r1066649_rule: Ubuntu 24.04 LTS must uniquely identify interactive users.
check_SV_270720r1066649_rule() {
    local status="fail"

    # Run command: awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd
    status=$(run_check "awk -F \":\" 'list[$3]++{print $1, $3}' /etc/passwd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270720r1066649_rule" "$status" "Ubuntu 24.04 LTS must uniquely identify interactive users."
}

# SV-270721r1066652_rule: Ubuntu 24.04 LTS must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts.
check_SV_270721r1066652_rule() {
    local status="fail"

    # Run command: grep -r pam_pkcs11.so /etc/pam.d/common-auth
    status=$(run_check "grep -r pam_pkcs11.so /etc/pam.d/common-auth")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270721r1066652_rule" "$status" "Ubuntu 24.04 LTS must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts."
}

# SV-270722r1067130_rule: Ubuntu 24.04 LTS must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts over SSH.
check_SV_270722r1067130_rule() {
    local status="fail"

    # Run command: sudo grep -r ^PubkeyAuthentication /etc/ssh/sshd_config*
    status=$(run_check "grep -r ^PubkeyAuthentication /etc/ssh/sshd_config*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270722r1067130_rule" "$status" "Ubuntu 24.04 LTS must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts over SSH."
}

# SV-270723r1066658_rule: Ubuntu 24.04 LTS must electronically verify Personal Identity Verification (PIV) credentials.
check_SV_270723r1066658_rule() {
    local status="fail"

    # Run command: sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ocsp_on
    status=$(run_check "grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ocsp_on")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270723r1066658_rule" "$status" "Ubuntu 24.04 LTS must electronically verify Personal Identity Verification (PIV) credentials."
}

# SV-270724r1066661_rule: Ubuntu 24.04 LTS must prevent direct login to the root account.
check_SV_270724r1066661_rule() {
    local status="fail"

    # Run command: sudo passwd -S root
    status=$(run_check "passwd -S root")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270724r1066661_rule" "$status" "Ubuntu 24.04 LTS must prevent direct login to the root account."
}

# SV-270725r1066664_rule: Ubuntu 24.04 LTS must store only encrypted representations of passwords.
check_SV_270725r1066664_rule() {
    local status="fail"

    # Run command: grep pam_unix.so /etc/pam.d/common-password
    status=$(run_check "grep pam_unix.so /etc/pam.d/common-password")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270725r1066664_rule" "$status" "Ubuntu 24.04 LTS must store only encrypted representations of passwords."
}

# SV-270726r1066667_rule: Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one uppercase character be used.
check_SV_270726r1066667_rule() {
    local status="fail"

    # Run command: grep -i "ucredit" /etc/security/pwquality.conf
    status=$(run_check "grep -i \"ucredit\" /etc/security/pwquality.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270726r1066667_rule" "$status" "Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one uppercase character be used."
}

# SV-270727r1066670_rule: Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one lowercase character be used.
check_SV_270727r1066670_rule() {
    local status="fail"

    # Run command: grep -i "lcredit" /etc/security/pwquality.conf
    status=$(run_check "grep -i \"lcredit\" /etc/security/pwquality.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270727r1066670_rule" "$status" "Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one lowercase character be used."
}

# SV-270728r1066673_rule: Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one numeric character be used.
check_SV_270728r1066673_rule() {
    local status="fail"

    # Run command: grep -i "dcredit" /etc/security/pwquality.conf
    status=$(run_check "grep -i \"dcredit\" /etc/security/pwquality.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270728r1066673_rule" "$status" "Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one numeric character be used."
}

# SV-270729r1066676_rule: Ubuntu 24.04 LTS must require the change of at least eight characters when passwords are changed.
check_SV_270729r1066676_rule() {
    local status="fail"

    # Run command: grep -i "difok" /etc/security/pwquality.conf
    status=$(run_check "grep -i \"difok\" /etc/security/pwquality.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270729r1066676_rule" "$status" "Ubuntu 24.04 LTS must require the change of at least eight characters when passwords are changed."
}

# SV-270730r1066679_rule: Ubuntu 24.04 LTS must enforce 24 hours/1 day as the minimum password lifetime. Passwords for new users must have a 24 hours/1 day minimum password lifetime restriction.
check_SV_270730r1066679_rule() {
    local status="fail"

    # Run command: grep -i ^PASS_MIN_DAYS /etc/login.defs
    status=$(run_check "grep -i ^PASS_MIN_DAYS /etc/login.defs")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270730r1066679_rule" "$status" "Ubuntu 24.04 LTS must enforce 24 hours/1 day as the minimum password lifetime. Passwords for new users must have a 24 hours/1 day minimum password lifetime restriction."
}

# SV-270731r1066682_rule: Ubuntu 24.04 LTS must enforce a 60-day maximum password lifetime restriction. Passwords for new users must have a 60-day maximum password lifetime restriction.
check_SV_270731r1066682_rule() {
    local status="fail"

    # Run command: grep -i ^PASS_MAX_DAYS /etc/login.defs
    status=$(run_check "grep -i ^PASS_MAX_DAYS /etc/login.defs")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270731r1066682_rule" "$status" "Ubuntu 24.04 LTS must enforce a 60-day maximum password lifetime restriction. Passwords for new users must have a 60-day maximum password lifetime restriction."
}

# SV-270732r1066685_rule: Ubuntu 24.04 LTS must enforce a minimum 15-character password length.
check_SV_270732r1066685_rule() {
    local status="fail"

    # Run command: grep -i minlen /etc/security/pwquality.conf
    status=$(run_check "grep -i minlen /etc/security/pwquality.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270732r1066685_rule" "$status" "Ubuntu 24.04 LTS must enforce a minimum 15-character password length."
}

# SV-270733r1066688_rule: Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one special character be used.
check_SV_270733r1066688_rule() {
    local status="fail"

    # Run command: grep -i "ocredit" /etc/security/pwquality.conf
    status=$(run_check "grep -i \"ocredit\" /etc/security/pwquality.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270733r1066688_rule" "$status" "Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one special character be used."
}

# SV-270734r1066691_rule: Ubuntu 24.04 LTS must be configured such that Pluggable Authentication Module (PAM) prohibits the use of cached authentications after one day.
check_SV_270734r1066691_rule() {
    local status="fail"

    # Run command: sudo grep offline_credentials_expiration /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf
    status=$(run_check "grep offline_credentials_expiration /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270734r1066691_rule" "$status" "Ubuntu 24.04 LTS must be configured such that Pluggable Authentication Module (PAM) prohibits the use of cached authentications after one day."
}

# SV-270735r1066694_rule: Ubuntu 24.04 LTS, for PKI-based authentication, SSSD must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.
check_SV_270735r1066694_rule() {
    local status="fail"

    # Run command: sudo grep -A 1 '^\[sssd\]' /etc/sssd/sssd.conf
    status=$(run_check "grep -A 1 '^\[sssd\]' /etc/sssd/sssd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo grep -A 1 '^\[pam]' /etc/sssd/sssd.conf
    status=$(run_check "grep -A 1 '^\[pam]' /etc/sssd/sssd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo grep certificate_verification /etc/sssd/sssd.conf
    status=$(run_check "grep certificate_verification /etc/sssd/sssd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270735r1066694_rule" "$status" "Ubuntu 24.04 LTS, for PKI-based authentication, SSSD must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor."
}

# SV-270736r1066697_rule: Ubuntu 24.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication.
check_SV_270736r1066697_rule() {
    local status="fail"

    # Run command: grep -i ldap_user_certificate /etc/sssd/sssd.conf
    status=$(run_check "grep -i ldap_user_certificate /etc/sssd/sssd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270736r1066697_rule" "$status" "Ubuntu 24.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication."
}

# SV-270737r1067178_rule: Ubuntu 24.04 LTS, for PKI-based authentication, Privileged Access Management (PAM) must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.
check_SV_270737r1067178_rule() {
    local status="fail"

    # Run command: sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ca
    status=$(run_check "grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ca")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270737r1067178_rule" "$status" "Ubuntu 24.04 LTS, for PKI-based authentication, Privileged Access Management (PAM) must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor."
}

# SV-270738r1066703_rule: Ubuntu 24.04 LTS for PKI-based authentication, must implement a local cache of revocation data in case of the inability to access revocation information via the network.
check_SV_270738r1066703_rule() {
    local status="fail"

    # Run command: grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep  -E -- 'crl_auto|crl_offline'
    status=$(run_check "grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep  -E -- 'crl_auto|crl_offline'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270738r1066703_rule" "$status" "Ubuntu 24.04 LTS for PKI-based authentication, must implement a local cache of revocation data in case of the inability to access revocation information via the network."
}

# SV-270739r1067124_rule: Ubuntu 24.04 LTS must encrypt all stored passwords with a FIPS 140-3 approved cryptographic hashing algorithm.
check_SV_270739r1067124_rule() {
    local status="fail"

    # Run command: grep -i ENCRYPT_METHOD /etc/login.defs
    status=$(run_check "grep -i ENCRYPT_METHOD /etc/login.defs")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270739r1067124_rule" "$status" "Ubuntu 24.04 LTS must encrypt all stored passwords with a FIPS 140-3 approved cryptographic hashing algorithm."
}

# SV-270740r1066709_rule: Ubuntu 24.04 LTS must generate audit records for privileged activities, nonlocal maintenance, diagnostic sessions, and other system-level access.
check_SV_270740r1066709_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep sudo.log
    status=$(run_check "auditctl -l | grep sudo.log")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270740r1066709_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for privileged activities, nonlocal maintenance, diagnostic sessions, and other system-level access."
}

# SV-270741r1066712_rule: Ubuntu 24.04 LTS must use strong authenticators in establishing nonlocal maintenance and diagnostic sessions.
check_SV_270741r1066712_rule() {
    local status="fail"

    # Run command: sudo grep -r ^UsePAM /etc/ssh/sshd_config*
    status=$(run_check "grep -r ^UsePAM /etc/ssh/sshd_config*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270741r1066712_rule" "$status" "Ubuntu 24.04 LTS must use strong authenticators in establishing nonlocal maintenance and diagnostic sessions."
}

# SV-270742r1066715_rule: Ubuntu 24.04 LTS must immediately terminate all network connections associated with SSH traffic after a period of inactivity.
check_SV_270742r1066715_rule() {
    local status="fail"

    # Run command: sudo grep -ir ClientAliveCountMax /etc/ssh/sshd_config*
    status=$(run_check "grep -ir ClientAliveCountMax /etc/ssh/sshd_config*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270742r1066715_rule" "$status" "Ubuntu 24.04 LTS must immediately terminate all network connections associated with SSH traffic after a period of inactivity."
}

# SV-270743r1066718_rule: Ubuntu 24.04 LTS must immediately terminate all network connections associated with SSH traffic at the end of the session or after 10 minutes of inactivity.
check_SV_270743r1066718_rule() {
    local status="fail"

    # Run command: grep -ir ClientAliveInterval /etc/ssh/sshd_config*
    status=$(run_check "grep -ir ClientAliveInterval /etc/ssh/sshd_config*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270743r1066718_rule" "$status" "Ubuntu 24.04 LTS must immediately terminate all network connections associated with SSH traffic at the end of the session or after 10 minutes of inactivity."
}

# SV-270744r1066721_rule: Ubuntu 24.04 LTS must implement NIST FIPS-validated cryptography to protect classified information and for the following: To provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.
check_SV_270744r1066721_rule() {
    local status="fail"

    # Run command: grep -i 1 /proc/sys/crypto/fips_enabled
    status=$(run_check "grep -i 1 /proc/sys/crypto/fips_enabled")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270744r1066721_rule" "$status" "Ubuntu 24.04 LTS must implement NIST FIPS-validated cryptography to protect classified information and for the following: To provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards."
}

# SV-270745r1066724_rule: Ubuntu 24.04 LTS must use DOD PKI-established certificate authorities (CAs) for verification of the establishment of protected sessions.
check_SV_270745r1066724_rule() {
    local status="fail"

    # Run command: grep -ir DOD /etc/ssl/certs
    status=$(run_check "grep -ir DOD /etc/ssl/certs")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270745r1066724_rule" "$status" "Ubuntu 24.04 LTS must use DOD PKI-established certificate authorities (CAs) for verification of the establishment of protected sessions."
}

# SV-270746r1066727_rule: Ubuntu 24.04 LTS must disable kernel core dumps.
check_SV_270746r1066727_rule() {
    local status="fail"

    # Run command: systemctl is-active kdump.service
    status=$(run_check "systemctl is-active kdump.service")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270746r1066727_rule" "$status" "Ubuntu 24.04 LTS must disable kernel core dumps."
}

# SV-270747r1066730_rule: Ubuntu 24.04 LTS handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.
check_SV_270747r1066730_rule() {
    local status="fail"

    # Run command: sudo fdisk -l
    status=$(run_check "fdisk -l")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: more /etc/crypttab
    status=$(run_check "more /etc/crypttab")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270747r1066730_rule" "$status" "Ubuntu 24.04 LTS handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest."
}

# SV-270748r1066733_rule: Ubuntu 24.04 LTS must ensure only users who need access to security functions are part of sudo group.
check_SV_270748r1066733_rule() {
    local status="fail"

    # Run command: grep sudo /etc/group
    status=$(run_check "grep /etc/group")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270748r1066733_rule" "$status" "Ubuntu 24.04 LTS must ensure only users who need access to security functions are part of sudo group."
}

# SV-270749r1067179_rule: Ubuntu 24.04 LTS must restrict access to the kernel message buffer.
check_SV_270749r1067179_rule() {
    local status="fail"

    # Run command: sysctl kernel.dmesg_restrict
    status=$(run_check "sysctl kernel.dmesg_restrict")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo grep -r kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
    status=$(run_check "grep -r kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270749r1067179_rule" "$status" "Ubuntu 24.04 LTS must restrict access to the kernel message buffer."
}

# SV-270750r1066739_rule: Ubuntu 24.04 LTS must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources.
check_SV_270750r1066739_rule() {
    local status="fail"

    # Run command: sudo find / -type d -perm -002 ! -perm -1000
    status=$(run_check "find / -type d -perm -002 ! -perm -1000")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270750r1066739_rule" "$status" "Ubuntu 24.04 LTS must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources."
}

# SV-270751r1066742_rule: Ubuntu 24.04 LTS must compare internal information system clocks at least every 24 hours with an authoritative time server.
check_SV_270751r1066742_rule() {
    local status="fail"

    # Run command: sudo grep -ir maxpoll /etc/chrony*
    status=$(run_check "grep -ir maxpoll /etc/chrony*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270751r1066742_rule" "$status" "Ubuntu 24.04 LTS must compare internal information system clocks at least every 24 hours with an authoritative time server."
}

# SV-270752r1068365_rule: Ubuntu 24.04 LTS must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second.
check_SV_270752r1068365_rule() {
    local status="fail"

    # Run command: grep makestep /etc/chrony/chrony.conf
    status=$(run_check "grep makestep /etc/chrony/chrony.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270752r1068365_rule" "$status" "Ubuntu 24.04 LTS must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second."
}

# SV-270753r1066748_rule: Ubuntu 24.04 LTS must be configured to use TCP syncookies.
check_SV_270753r1066748_rule() {
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
    log_result "SV-270753r1066748_rule" "$status" "Ubuntu 24.04 LTS must be configured to use TCP syncookies."
}

# SV-270754r1066751_rule: Ubuntu 24.04 LTS must configure the uncomplicated firewall to rate-limit impacted network interfaces.
check_SV_270754r1066751_rule() {
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
    log_result "SV-270754r1066751_rule" "$status" "Ubuntu 24.04 LTS must configure the uncomplicated firewall to rate-limit impacted network interfaces."
}

# SV-270755r1066754_rule: Ubuntu 24.04 LTS must disable all wireless network adapters.
check_SV_270755r1066754_rule() {
    local status="fail"

    # Run command: ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename
    status=$(run_check "ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270755r1066754_rule" "$status" "Ubuntu 24.04 LTS must disable all wireless network adapters."
}

# SV-270756r1066757_rule: Ubuntu 24.04 LTS must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.
check_SV_270756r1066757_rule() {
    local status="fail"

    # Run command: sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c "%n %a" {} \;
    status=$(run_check "find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c \"%n %a\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270756r1066757_rule" "$status" "Ubuntu 24.04 LTS must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries."
}

# SV-270757r1066760_rule: Ubuntu 24.04 LTS must generate system journal entries without revealing information that could be exploited by adversaries.
check_SV_270757r1066760_rule() {
    local status="fail"

    # Run command: sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %a" {} \;
    status=$(run_check "find /run/log/journal /var/log/journal  -type d -exec stat -c \"%n %a\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %a" {} \;
    status=$(run_check "find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %a\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270757r1066760_rule" "$status" "Ubuntu 24.04 LTS must generate system journal entries without revealing information that could be exploited by adversaries."
}

# SV-270758r1066763_rule: Ubuntu 24.04 LTS must be configured so that the "journalctl" command is not accessible by unauthorized users.
check_SV_270758r1066763_rule() {
    local status="fail"

    # Run command: sudo find /usr/bin/journalctl -exec stat -c "%n %a" {} \;
    status=$(run_check "find /usr/bin/journalctl -exec stat -c \"%n %a\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270758r1066763_rule" "$status" "Ubuntu 24.04 LTS must be configured so that the "journalctl" command is not accessible by unauthorized users."
}

# SV-270759r1068367_rule: Ubuntu 24.04 LTS must be configured so that the "journalctl" command is owned by "root".
check_SV_270759r1068367_rule() {
    local status="fail"

    # Run command: sudo find /usr/bin/journalctl -exec stat -c "%n %U" {} \;
    status=$(run_check "find /usr/bin/journalctl -exec stat -c \"%n %U\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270759r1068367_rule" "$status" "Ubuntu 24.04 LTS must be configured so that the "journalctl" command is owned by "root"."
}

# SV-270760r1066769_rule: Ubuntu 24.04 LTS must be configured so that the "journalctl" command is group-owned by "root".
check_SV_270760r1066769_rule() {
    local status="fail"

    # Run command: sudo find /usr/bin/journalctl -exec stat -c "%n %G" {} \;
    status=$(run_check "find /usr/bin/journalctl -exec stat -c \"%n %G\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270760r1066769_rule" "$status" "Ubuntu 24.04 LTS must be configured so that the "journalctl" command is group-owned by "root"."
}

# SV-270761r1067180_rule: Ubuntu 24.04 LTS must configure the directories used by the system journal to be group-owned by "systemd-journal".
check_SV_270761r1067180_rule() {
    local status="fail"

    # Run command: sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %G" {} \;
    status=$(run_check "find /run/log/journal /var/log/journal  -type d -exec stat -c \"%n %G\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270761r1067180_rule" "$status" "Ubuntu 24.04 LTS must configure the directories used by the system journal to be group-owned by "systemd-journal"."
}

# SV-270762r1066775_rule: Ubuntu 24.04 LTS must configure the files used by the system journal to be group-owned by "systemd-journal".
check_SV_270762r1066775_rule() {
    local status="fail"

    # Run command: sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %G" {} \;
    status=$(run_check "find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %G\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270762r1066775_rule" "$status" "Ubuntu 24.04 LTS must configure the files used by the system journal to be group-owned by "systemd-journal"."
}

# SV-270763r1066778_rule: Ubuntu 24.04 LTS must configure the directories used by the system journal to be owned by "root".
check_SV_270763r1066778_rule() {
    local status="fail"

    # Run command: sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %U" {} \;
    status=$(run_check "find /run/log/journal /var/log/journal  -type d -exec stat -c \"%n %U\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270763r1066778_rule" "$status" "Ubuntu 24.04 LTS must configure the directories used by the system journal to be owned by "root"."
}

# SV-270764r1066781_rule: Ubuntu 24.04 LTS must configure the files used by the system journal to be owned by "root"
check_SV_270764r1066781_rule() {
    local status="fail"

    # Run command: sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %U" {} \;
    status=$(run_check "find /run/log/journal /var/log/journal  -type f -exec stat -c \"%n %U\" {} \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270764r1066781_rule" "$status" "Ubuntu 24.04 LTS must configure the files used by the system journal to be owned by "root""
}

# SV-270765r1066784_rule: Ubuntu 24.04 LTS must configure the /var/log directory to be group-owned by syslog.
check_SV_270765r1066784_rule() {
    local status="fail"

    # Run command: stat -c "%n %G" /var/log
    status=$(run_check "stat -c \"%n %G\" /var/log")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270765r1066784_rule" "$status" "Ubuntu 24.04 LTS must configure the /var/log directory to be group-owned by syslog."
}

# SV-270766r1066787_rule: Ubuntu 24.04 LTS must configure the /var/log directory to be owned by root.
check_SV_270766r1066787_rule() {
    local status="fail"

    # Run command: stat -c "%n %U" /var/log
    status=$(run_check "stat -c \"%n %U\" /var/log")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270766r1066787_rule" "$status" "Ubuntu 24.04 LTS must configure the /var/log directory to be owned by root."
}

# SV-270767r1066790_rule: Ubuntu 24.04 LTS must configure the /var/log directory to have mode "0755" or less permissive.
check_SV_270767r1066790_rule() {
    local status="fail"

    # Run command: stat -c "%n %a" /var/log
    status=$(run_check "stat -c \"%n %a\" /var/log")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270767r1066790_rule" "$status" "Ubuntu 24.04 LTS must configure the /var/log directory to have mode "0755" or less permissive."
}

# SV-270768r1066793_rule: Ubuntu 24.04 LTS must configure the /var/log/syslog file to be group-owned by adm.
check_SV_270768r1066793_rule() {
    local status="fail"

    # Run command: stat -c "%n %G" /var/log/syslog
    status=$(run_check "stat -c \"%n %G\" /var/log/syslog")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270768r1066793_rule" "$status" "Ubuntu 24.04 LTS must configure the /var/log/syslog file to be group-owned by adm."
}

# SV-270769r1066796_rule: Ubuntu 24.04 LTS must configure /var/log/syslog file to be owned by syslog.
check_SV_270769r1066796_rule() {
    local status="fail"

    # Run command: stat -c "%n %U" /var/log/syslog
    status=$(run_check "stat -c \"%n %U\" /var/log/syslog")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270769r1066796_rule" "$status" "Ubuntu 24.04 LTS must configure /var/log/syslog file to be owned by syslog."
}

# SV-270770r1066799_rule: Ubuntu 24.04 LTS must configure /var/log/syslog file with mode "0640" or less permissive.
check_SV_270770r1066799_rule() {
    local status="fail"

    # Run command: stat -c "%n %a" /var/log/syslog
    status=$(run_check "stat -c \"%n %a\" /var/log/syslog")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270770r1066799_rule" "$status" "Ubuntu 24.04 LTS must configure /var/log/syslog file with mode "0640" or less permissive."
}

# SV-270771r1066802_rule: Ubuntu 24.04 LTS must implement nonexecutable data to protect its memory from unauthorized code execution.
check_SV_270771r1066802_rule() {
    local status="fail"

    # Run command: sudo dmesg | grep -i "execute disable"
    status=$(run_check "dmesg | grep -i \"execute disable\"")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: grep flags /proc/cpuinfo | grep -w nx | sort -u
    status=$(run_check "grep flags /proc/cpuinfo | grep -w nx | sort -u")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270771r1066802_rule" "$status" "Ubuntu 24.04 LTS must implement nonexecutable data to protect its memory from unauthorized code execution."
}

# SV-270772r1066805_rule: Ubuntu 24.04 LTS must implement address space layout randomization to protect its memory from unauthorized code execution.
check_SV_270772r1066805_rule() {
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

    # Run command: sudo egrep -R "^kernel.randomize_va_space=[^2]" /etc/sysctl.conf /etc/sysctl.d
    status=$(run_check "egrep -R \"^kernel.randomize_va_space=[^2]\" /etc/sysctl.conf /etc/sysctl.d")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270772r1066805_rule" "$status" "Ubuntu 24.04 LTS must implement address space layout randomization to protect its memory from unauthorized code execution."
}

# SV-270773r1066808_rule: Ubuntu 24.04 LTS must be configured so that Advance Package Tool (APT) removes all software components after updated versions have been installed.
check_SV_270773r1066808_rule() {
    local status="fail"

    # Run command: grep -i remove-unused /etc/apt/apt.conf.d/50unattended-upgrades
    status=$(run_check "grep -i remove-unused /etc/apt/apt.conf.d/50unattended-upgrades")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270773r1066808_rule" "$status" "Ubuntu 24.04 LTS must be configured so that Advance Package Tool (APT) removes all software components after updated versions have been installed."
}

# SV-270774r1066811_rule: Ubuntu 24.04 LTS must be a vendor-supported release.
check_SV_270774r1066811_rule() {
    local status="fail"

    # Run command: grep DISTRIB_DESCRIPTION /etc/lsb-release
    status=$(run_check "grep DISTRIB_DESCRIPTION /etc/lsb-release")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270774r1066811_rule" "$status" "Ubuntu 24.04 LTS must be a vendor-supported release."
}

# SV-270775r1068369_rule: Ubuntu 24.04 LTS must be configured so that audit configuration files are not write-accessible by unauthorized users.
check_SV_270775r1068369_rule() {
    local status="fail"

    # Run command: sudo ls -al /etc/audit/ /etc/audit/rules.d/
    status=$(run_check "ls -al /etc/audit/ /etc/audit/rules.d/")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270775r1068369_rule" "$status" "Ubuntu 24.04 LTS must be configured so that audit configuration files are not write-accessible by unauthorized users."
}

# SV-270776r1066817_rule: Ubuntu 24.04 LTS must permit only authorized accounts to own the audit configuration files.
check_SV_270776r1066817_rule() {
    local status="fail"

    # Run command: sudo ls -al /etc/audit/ /etc/audit/rules.d/
    status=$(run_check "ls -al /etc/audit/ /etc/audit/rules.d/")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270776r1066817_rule" "$status" "Ubuntu 24.04 LTS must permit only authorized accounts to own the audit configuration files."
}

# SV-270777r1066820_rule: Ubuntu 24.04 LTS must permit only authorized groups to own the audit configuration files.
check_SV_270777r1066820_rule() {
    local status="fail"

    # Run command: sudo ls -al /etc/audit/ /etc/audit/rules.d/
    status=$(run_check "ls -al /etc/audit/ /etc/audit/rules.d/")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270777r1066820_rule" "$status" "Ubuntu 24.04 LTS must permit only authorized groups to own the audit configuration files."
}

# SV-270778r1066823_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the su command.
check_SV_270778r1066823_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep /bin/su
    status=$(run_check "auditctl -l | grep /bin/su")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270778r1066823_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the su command."
}

# SV-270779r1066826_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chfn command.
check_SV_270779r1066826_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep /usr/bin/chfn
    status=$(run_check "auditctl -l | grep /usr/bin/chfn")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270779r1066826_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chfn command."
}

# SV-270780r1066829_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the mount command.
check_SV_270780r1066829_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep /usr/bin/mount
    status=$(run_check "auditctl -l | grep /usr/bin/mount")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270780r1066829_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the mount command."
}

# SV-270781r1066832_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the umount command.
check_SV_270781r1066832_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep /usr/bin/umount
    status=$(run_check "auditctl -l | grep /usr/bin/umount")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270781r1066832_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the umount command."
}

# SV-270782r1066835_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the ssh-agent command.
check_SV_270782r1066835_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep /usr/bin/ssh-agent
    status=$(run_check "auditctl -l | grep /usr/bin/ssh-agent")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270782r1066835_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the ssh-agent command."
}

# SV-270783r1066838_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the ssh-keysign command.
check_SV_270783r1066838_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep ssh-keysign
    status=$(run_check "auditctl -l | grep ssh-keysign")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270783r1066838_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the ssh-keysign command."
}

# SV-270784r1068371_rule: Ubuntu 24.04 LTS must generate audit records for any use of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls.
check_SV_270784r1068371_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep xattr
    status=$(run_check "auditctl -l | grep xattr")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270784r1068371_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for any use of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls."
}

# SV-270785r1068373_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chown, fchown, fchownat, and lchown system calls.
check_SV_270785r1068373_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep chown
    status=$(run_check "auditctl -l | grep chown")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270785r1068373_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chown, fchown, fchownat, and lchown system calls."
}

# SV-270786r1068375_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chmod, fchmod, and fchmodat system calls.
check_SV_270786r1068375_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep chmod
    status=$(run_check "auditctl -l | grep chmod")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270786r1068375_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chmod, fchmod, and fchmodat system calls."
}

# SV-270787r1068378_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls.
check_SV_270787r1068378_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep 'open\|truncate\|creat'
    status=$(run_check "auditctl -l | grep 'open\|truncate\|creat'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270787r1068378_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls."
}

# SV-270788r1066853_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the sudo command.
check_SV_270788r1066853_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep /usr/bin/sudo
    status=$(run_check "auditctl -l | grep /usr/bin/sudo")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270788r1066853_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the sudo command."
}

# SV-270789r1066856_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the sudoedit command.
check_SV_270789r1066856_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep /usr/bin/sudoedit
    status=$(run_check "auditctl -l | grep /usr/bin/sudoedit")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270789r1066856_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the sudoedit command."
}

# SV-270790r1068380_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chsh command.
check_SV_270790r1068380_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep chsh
    status=$(run_check "auditctl -l | grep chsh")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270790r1068380_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chsh command."
}

# SV-270791r1066862_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the newgrp command.
check_SV_270791r1066862_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep newgrp
    status=$(run_check "auditctl -l | grep newgrp")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270791r1066862_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the newgrp command."
}

# SV-270792r1066865_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chcon command.
check_SV_270792r1066865_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep chcon
    status=$(run_check "auditctl -l | grep chcon")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270792r1066865_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chcon command."
}

# SV-270793r1066868_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the apparmor_parser command.
check_SV_270793r1066868_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep apparmor_parser
    status=$(run_check "auditctl -l | grep apparmor_parser")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270793r1066868_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the apparmor_parser command."
}

# SV-270794r1066871_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the setfacl command.
check_SV_270794r1066871_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep setfacl
    status=$(run_check "auditctl -l | grep setfacl")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270794r1066871_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the setfacl command."
}

# SV-270795r1066874_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chacl command.
check_SV_270795r1066874_rule() {
    local status="fail"

    # Run command: sudo audtctl -l | grep chacl
    status=$(run_check "audtctl -l | grep chacl")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270795r1066874_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chacl command."
}

# SV-270796r1066877_rule: Ubuntu 24.04 LTS must generate audit records for the use and modification of faillog file.
check_SV_270796r1066877_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep faillog
    status=$(run_check "auditctl -l | grep faillog")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270796r1066877_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for the use and modification of faillog file."
}

# SV-270797r1066880_rule: Ubuntu 24.04 LTS must generate audit records for the use and modification of the lastlog file.
check_SV_270797r1066880_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep lastlog
    status=$(run_check "auditctl -l | grep lastlog")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270797r1066880_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for the use and modification of the lastlog file."
}

# SV-270798r1068382_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the passwd command.
check_SV_270798r1068382_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep -w passwd
    status=$(run_check "auditctl -l | grep -w passwd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270798r1068382_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the passwd command."
}

# SV-270799r1066886_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the unix_update command.
check_SV_270799r1066886_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep -w unix_update
    status=$(run_check "auditctl -l | grep -w unix_update")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270799r1066886_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the unix_update command."
}

# SV-270800r1066889_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the gpasswd command.
check_SV_270800r1066889_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep -w gpasswd
    status=$(run_check "auditctl -l | grep -w gpasswd")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270800r1066889_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the gpasswd command."
}

# SV-270801r1066892_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chage command.
check_SV_270801r1066892_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep -w chage
    status=$(run_check "auditctl -l | grep -w chage")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270801r1066892_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chage command."
}

# SV-270802r1066895_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the usermod command.
check_SV_270802r1066895_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep -w usermod
    status=$(run_check "auditctl -l | grep -w usermod")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270802r1066895_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the usermod command."
}

# SV-270803r1066898_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the crontab command.
check_SV_270803r1066898_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep -w crontab
    status=$(run_check "auditctl -l | grep -w crontab")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270803r1066898_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the crontab command."
}

# SV-270804r1066901_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the pam_timestamp_check command.
check_SV_270804r1066901_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep -w pam_timestamp_check
    status=$(run_check "auditctl -l | grep -w pam_timestamp_check")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270804r1066901_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the pam_timestamp_check command."
}

# SV-270805r1068384_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the init_module and finit_module syscalls.
check_SV_270805r1068384_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep init_module
    status=$(run_check "auditctl -l | grep init_module")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270805r1068384_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the init_module and finit_module syscalls."
}

# SV-270806r1068386_rule: Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the delete_module syscall.
check_SV_270806r1068386_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep -w delete_module
    status=$(run_check "auditctl -l | grep -w delete_module")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270806r1068386_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the delete_module syscall."
}

# SV-270807r1066910_rule: Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers file occur.
check_SV_270807r1066910_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep sudoers
    status=$(run_check "auditctl -l | grep sudoers")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270807r1066910_rule" "$status" "Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers file occur."
}

# SV-270808r1067100_rule: Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers.d directory occur.
check_SV_270808r1067100_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep sudoers.d
    status=$(run_check "auditctl -l | grep sudoers.d")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270808r1067100_rule" "$status" "Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers.d directory occur."
}

# SV-270809r1068388_rule: Ubuntu 24.04 LTS must generate audit records for any successful/unsuccessful use of unlink, unlinkat, rename, renameat, and rmdir system calls.
check_SV_270809r1068388_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep 'unlink\|rename\|rmdir'
    status=$(run_check "auditctl -l | grep 'unlink\|rename\|rmdir'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270809r1068388_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for any successful/unsuccessful use of unlink, unlinkat, rename, renameat, and rmdir system calls."
}

# SV-270810r1066919_rule: Ubuntu 24.04 LTS must generate audit records for the /var/log/wtmp file.
check_SV_270810r1066919_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep '/var/log/wtmp'
    status=$(run_check "auditctl -l | grep '/var/log/wtmp'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270810r1066919_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for the /var/log/wtmp file."
}

# SV-270811r1066922_rule: Ubuntu 24.04 LTS must generate audit records for the /var/run/utmp file.
check_SV_270811r1066922_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep '/var/run/utmp'
    status=$(run_check "auditctl -l | grep '/var/run/utmp'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270811r1066922_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for the /var/run/utmp file."
}

# SV-270812r1066925_rule: Ubuntu 24.04 LTS must generate audit records for the /var/log/btmp file.
check_SV_270812r1066925_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep '/var/log/btmp'
    status=$(run_check "auditctl -l | grep '/var/log/btmp'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270812r1066925_rule" "$status" "Ubuntu 24.04 LTS must generate audit records for the /var/log/btmp file."
}

# SV-270813r1066928_rule: Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to use modprobe command.
check_SV_270813r1066928_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep '/sbin/modprobe'
    status=$(run_check "auditctl -l | grep '/sbin/modprobe'")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270813r1066928_rule" "$status" "Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to use modprobe command."
}

# SV-270814r1066931_rule: Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to use the kmod command.
check_SV_270814r1066931_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep kmod
    status=$(run_check "auditctl -l | grep kmod")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270814r1066931_rule" "$status" "Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to use the kmod command."
}

# SV-270815r1066934_rule: Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to use the fdisk command.
check_SV_270815r1066934_rule() {
    local status="fail"

    # Run command: sudo auditctl -l | grep fdisk
    status=$(run_check "auditctl -l | grep fdisk")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270815r1066934_rule" "$status" "Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to use the fdisk command."
}

# SV-270816r1066937_rule: Ubuntu 24.04 LTS must allocate audit record storage capacity to store at least one week's worth of audit records, when audit records are not immediately sent to a central audit record storage facility.
check_SV_270816r1066937_rule() {
    local status="fail"

    # Run command: sudo grep ^log_file /etc/audit/auditd.conf
    status=$(run_check "grep ^log_file /etc/audit/auditd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo df -h /var/log/audit/
    status=$(run_check "df -h /var/log/audit/")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo du -sh [audit_partition]
    status=$(run_check "du -sh [audit_partition]")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270816r1066937_rule" "$status" "Ubuntu 24.04 LTS must allocate audit record storage capacity to store at least one week's worth of audit records, when audit records are not immediately sent to a central audit record storage facility."
}

# SV-270817r1066940_rule: Ubuntu 24.04 LTS must have a crontab script running weekly to offload audit events of standalone systems.
check_SV_270817r1066940_rule() {
    local status="fail"

    # Run command: ls /etc/cron.weekly
    status=$(run_check "ls /etc/cron.weekly")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270817r1066940_rule" "$status" "Ubuntu 24.04 LTS must have a crontab script running weekly to offload audit events of standalone systems."
}

# SV-270818r1066943_rule: Ubuntu 24.04 LTS must immediately notify the system administrator (SA) and information system security officer (ISSO) (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.
check_SV_270818r1066943_rule() {
    local status="fail"

    # Run command: sudo grep ^space_left_action /etc/audit/auditd.conf
    status=$(run_check "grep ^space_left_action /etc/audit/auditd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo grep ^space_left /etc/audit/auditd.conf
    status=$(run_check "grep ^space_left /etc/audit/auditd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo grep ^action_mail_acct /etc/audit/auditd.conf
    status=$(run_check "grep ^action_mail_acct /etc/audit/auditd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270818r1066943_rule" "$status" "Ubuntu 24.04 LTS must immediately notify the system administrator (SA) and information system security officer (ISSO) (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity."
}

# SV-270819r1068390_rule: Ubuntu 24.04 LTS must alert the system administrator (SA) and information system security officer (ISSO) (at a minimum) in the event of an audit processing failure.
check_SV_270819r1068390_rule() {
    local status="fail"

    # Run command: sudo grep '^action_mail_acct' /etc/audit/auditd.conf
    status=$(run_check "grep '^action_mail_acct' /etc/audit/auditd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270819r1068390_rule" "$status" "Ubuntu 24.04 LTS must alert the system administrator (SA) and information system security officer (ISSO) (at a minimum) in the event of an audit processing failure."
}

# SV-270820r1066949_rule: Ubuntu 24.04 LTS must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).
check_SV_270820r1066949_rule() {
    local status="fail"

    # Run command: timedatectl status | grep -i "time zone"
    status=$(run_check "timedatectl status | grep -i \"time zone\"")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270820r1066949_rule" "$status" "Ubuntu 24.04 LTS must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT)."
}

# SV-270821r1068391_rule: Ubuntu 24.04 LTS must configure audit tools with a mode of "0755" or less permissive.
check_SV_270821r1068391_rule() {
    local status="fail"

    # Run command: stat -c "%n %a" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules
    status=$(run_check "stat -c \"%n %a\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270821r1068391_rule" "$status" "Ubuntu 24.04 LTS must configure audit tools with a mode of "0755" or less permissive."
}

# SV-270822r1068392_rule: Ubuntu 24.04 LTS must configure audit tools to be owned by root.
check_SV_270822r1068392_rule() {
    local status="fail"

    # Run command: stat -c "%n %U" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules
    status=$(run_check "stat -c \"%n %U\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270822r1068392_rule" "$status" "Ubuntu 24.04 LTS must configure audit tools to be owned by root."
}

# SV-270823r1068393_rule: Ubuntu 24.04 LTS must configure the audit tools to be group-owned by root.
check_SV_270823r1068393_rule() {
    local status="fail"

    # Run command: stat -c "%n %G" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules
    status=$(run_check "stat -c \"%n %G\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270823r1068393_rule" "$status" "Ubuntu 24.04 LTS must configure the audit tools to be group-owned by root."
}

# SV-270824r1066961_rule: Ubuntu 24.04 LTS must have directories that contain system commands set to a mode of "0755" or less permissive.
check_SV_270824r1066961_rule() {
    local status="fail"

    # Run command: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" '{}' \;
    status=$(run_check "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c \"%n %a\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270824r1066961_rule" "$status" "Ubuntu 24.04 LTS must have directories that contain system commands set to a mode of "0755" or less permissive."
}

# SV-270825r1066964_rule: Ubuntu 24.04 LTS must have directories that contain system commands owned by root.
check_SV_270825r1066964_rule() {
    local status="fail"

    # Run command: sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' \;
    status=$(run_check "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c \"%n %U\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270825r1066964_rule" "$status" "Ubuntu 24.04 LTS must have directories that contain system commands owned by root."
}

# SV-270826r1066967_rule: Ubuntu 24.04 LTS must have directories that contain system commands group-owned by root.
check_SV_270826r1066967_rule() {
    local status="fail"

    # Run command: sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c "%n %G" '{}' \;
    status=$(run_check "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c \"%n %G\" '{}' \;")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270826r1066967_rule" "$status" "Ubuntu 24.04 LTS must have directories that contain system commands group-owned by root."
}

# SV-270827r1066970_rule: Ubuntu 24.04 LTS must be configured so that audit log files are not read or write-accessible by unauthorized users.
check_SV_270827r1066970_rule() {
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
    log_result "SV-270827r1066970_rule" "$status" "Ubuntu 24.04 LTS must be configured so that audit log files are not read or write-accessible by unauthorized users."
}

# SV-270828r1066973_rule: Ubuntu 24.04 LTS must be configured to permit only authorized users ownership of the audit log files.
check_SV_270828r1066973_rule() {
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
    log_result "SV-270828r1066973_rule" "$status" "Ubuntu 24.04 LTS must be configured to permit only authorized users ownership of the audit log files."
}

# SV-270829r1066976_rule: Ubuntu 24.04 LTS must permit only authorized groups ownership of the audit log files.
check_SV_270829r1066976_rule() {
    local status="fail"

    # Run command: sudo grep -iw log_group /etc/audit/auditd.conf
    status=$(run_check "grep -iw log_group /etc/audit/auditd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo grep -iw log_file /etc/audit/auditd.conf
    status=$(run_check "grep -iw log_file /etc/audit/auditd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo stat -c "%n %G" /var/log/audit/*
    status=$(run_check "stat -c \"%n %G\" /var/log/audit/*")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270829r1066976_rule" "$status" "Ubuntu 24.04 LTS must permit only authorized groups ownership of the audit log files."
}

# SV-270830r1068397_rule: Ubuntu 24.04 LTS must be configured so that the audit log directory is not write-accessible by unauthorized users.
check_SV_270830r1068397_rule() {
    local status="fail"

    # Run command: sudo grep -iw ^log_file /etc/audit/auditd.conf
    status=$(run_check "grep -iw ^log_file /etc/audit/auditd.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Run command: sudo stat -c "%n %a" /var/log/audit
    status=$(run_check "stat -c \"%n %a\" /var/log/audit")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270830r1068397_rule" "$status" "Ubuntu 24.04 LTS must be configured so that the audit log directory is not write-accessible by unauthorized users."
}

# SV-270831r1066982_rule: Ubuntu 24.04 LTS must use cryptographic mechanisms to protect the integrity of audit tools.
check_SV_270831r1066982_rule() {
    local status="fail"

    # Run command: egrep '(\/sbin\/(audit|au))' /etc/aide/aide.conf
    status=$(run_check "egrep '(\/sbin\/(audit|au))' /etc/aide/aide.conf")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270831r1066982_rule" "$status" "Ubuntu 24.04 LTS must use cryptographic mechanisms to protect the integrity of audit tools."
}

# SV-270832r1068399_rule: Ubuntu 24.04 LTS audit system must protect auditing rules from unauthorized change.
check_SV_270832r1068399_rule() {
    local status="fail"

    # Run command: grep -E '^-e 2' /etc/audit/audit.rules
    status=$(run_check "grep -E '^-e 2' /etc/audit/audit.rules")
    if [ "$status" == "manual" ]; then
        break
    fi

    # Log result
    log_result "SV-270832r1068399_rule" "$status" "Ubuntu 24.04 LTS audit system must protect auditing rules from unauthorized change."
}

# Execute all checks
check_SV_270645r1068357_rule
check_SV_270646r1068358_rule
check_SV_270647r1066430_rule
check_SV_270648r1066433_rule
check_SV_270649r1067136_rule
check_SV_270650r1066439_rule
check_SV_270651r1068395_rule
check_SV_270652r1067138_rule
check_SV_270653r1067141_rule
check_SV_270654r1067143_rule
check_SV_270655r1067145_rule
check_SV_270656r1067148_rule
check_SV_270657r1066460_rule
check_SV_270658r1067151_rule
check_SV_270659r1066466_rule
check_SV_270660r1066469_rule
check_SV_270661r1067175_rule
check_SV_270662r1067156_rule
check_SV_270663r1066478_rule
check_SV_270664r1068359_rule
check_SV_270665r1067133_rule
check_SV_270666r1066487_rule
check_SV_270667r1067107_rule
check_SV_270668r1067110_rule
check_SV_270669r1067112_rule
check_SV_270670r1067115_rule
check_SV_270671r1067118_rule
check_SV_270672r1067161_rule
check_SV_270673r1067164_rule
check_SV_270674r1067167_rule
check_SV_270675r1066514_rule
check_SV_270676r1068360_rule
check_SV_270677r1066520_rule
check_SV_270678r1066523_rule
check_SV_270679r1066526_rule
check_SV_270680r1066529_rule
check_SV_270681r1066532_rule
check_SV_270682r1066535_rule
check_SV_270683r1066538_rule
check_SV_270684r1066541_rule
check_SV_270685r1066544_rule
check_SV_270686r1066547_rule
check_SV_270687r1066550_rule
check_SV_270688r1066553_rule
check_SV_270689r1066556_rule
check_SV_270690r1067126_rule
check_SV_270691r1066562_rule
check_SV_270692r1066565_rule
check_SV_270693r1066568_rule
check_SV_270694r1066571_rule
check_SV_270695r1066574_rule
check_SV_270696r1066577_rule
check_SV_270697r1066580_rule
check_SV_270698r1066583_rule
check_SV_270699r1066586_rule
check_SV_270700r1066589_rule
check_SV_270701r1066592_rule
check_SV_270702r1066595_rule
check_SV_270703r1066598_rule
check_SV_270704r1066601_rule
check_SV_270705r1066604_rule
check_SV_270706r1068361_rule
check_SV_270707r1066610_rule
check_SV_270708r1066613_rule
check_SV_270709r1066616_rule
check_SV_270710r1066619_rule
check_SV_270711r1066622_rule
check_SV_270712r1068363_rule
check_SV_270713r1066628_rule
check_SV_270714r1067119_rule
check_SV_270715r1066634_rule
check_SV_270716r1066637_rule
check_SV_270717r1067177_rule
check_SV_270718r1067128_rule
check_SV_270719r1067172_rule
check_SV_270720r1066649_rule
check_SV_270721r1066652_rule
check_SV_270722r1067130_rule
check_SV_270723r1066658_rule
check_SV_270724r1066661_rule
check_SV_270725r1066664_rule
check_SV_270726r1066667_rule
check_SV_270727r1066670_rule
check_SV_270728r1066673_rule
check_SV_270729r1066676_rule
check_SV_270730r1066679_rule
check_SV_270731r1066682_rule
check_SV_270732r1066685_rule
check_SV_270733r1066688_rule
check_SV_270734r1066691_rule
check_SV_270735r1066694_rule
check_SV_270736r1066697_rule
check_SV_270737r1067178_rule
check_SV_270738r1066703_rule
check_SV_270739r1067124_rule
check_SV_270740r1066709_rule
check_SV_270741r1066712_rule
check_SV_270742r1066715_rule
check_SV_270743r1066718_rule
check_SV_270744r1066721_rule
check_SV_270745r1066724_rule
check_SV_270746r1066727_rule
check_SV_270747r1066730_rule
check_SV_270748r1066733_rule
check_SV_270749r1067179_rule
check_SV_270750r1066739_rule
check_SV_270751r1066742_rule
check_SV_270752r1068365_rule
check_SV_270753r1066748_rule
check_SV_270754r1066751_rule
check_SV_270755r1066754_rule
check_SV_270756r1066757_rule
check_SV_270757r1066760_rule
check_SV_270758r1066763_rule
check_SV_270759r1068367_rule
check_SV_270760r1066769_rule
check_SV_270761r1067180_rule
check_SV_270762r1066775_rule
check_SV_270763r1066778_rule
check_SV_270764r1066781_rule
check_SV_270765r1066784_rule
check_SV_270766r1066787_rule
check_SV_270767r1066790_rule
check_SV_270768r1066793_rule
check_SV_270769r1066796_rule
check_SV_270770r1066799_rule
check_SV_270771r1066802_rule
check_SV_270772r1066805_rule
check_SV_270773r1066808_rule
check_SV_270774r1066811_rule
check_SV_270775r1068369_rule
check_SV_270776r1066817_rule
check_SV_270777r1066820_rule
check_SV_270778r1066823_rule
check_SV_270779r1066826_rule
check_SV_270780r1066829_rule
check_SV_270781r1066832_rule
check_SV_270782r1066835_rule
check_SV_270783r1066838_rule
check_SV_270784r1068371_rule
check_SV_270785r1068373_rule
check_SV_270786r1068375_rule
check_SV_270787r1068378_rule
check_SV_270788r1066853_rule
check_SV_270789r1066856_rule
check_SV_270790r1068380_rule
check_SV_270791r1066862_rule
check_SV_270792r1066865_rule
check_SV_270793r1066868_rule
check_SV_270794r1066871_rule
check_SV_270795r1066874_rule
check_SV_270796r1066877_rule
check_SV_270797r1066880_rule
check_SV_270798r1068382_rule
check_SV_270799r1066886_rule
check_SV_270800r1066889_rule
check_SV_270801r1066892_rule
check_SV_270802r1066895_rule
check_SV_270803r1066898_rule
check_SV_270804r1066901_rule
check_SV_270805r1068384_rule
check_SV_270806r1068386_rule
check_SV_270807r1066910_rule
check_SV_270808r1067100_rule
check_SV_270809r1068388_rule
check_SV_270810r1066919_rule
check_SV_270811r1066922_rule
check_SV_270812r1066925_rule
check_SV_270813r1066928_rule
check_SV_270814r1066931_rule
check_SV_270815r1066934_rule
check_SV_270816r1066937_rule
check_SV_270817r1066940_rule
check_SV_270818r1066943_rule
check_SV_270819r1068390_rule
check_SV_270820r1066949_rule
check_SV_270821r1068391_rule
check_SV_270822r1068392_rule
check_SV_270823r1068393_rule
check_SV_270824r1066961_rule
check_SV_270825r1066964_rule
check_SV_270826r1066967_rule
check_SV_270827r1066970_rule
check_SV_270828r1066973_rule
check_SV_270829r1066976_rule
check_SV_270830r1068397_rule
check_SV_270831r1066982_rule
check_SV_270832r1068399_rule

# Generate final report
generate_report
