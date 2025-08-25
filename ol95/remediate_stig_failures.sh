#!/bin/bash
#
# Oracle Linux 9 STIG Remediation Script
# This script remediates the failed STIG findings from the OpenSCAP report
#
# WARNING: This script makes system-wide changes. Review carefully before running.
# BACKUP your system before running this script in production.
#
# Usage: sudo ./remediate_stig_failures.sh [--dry-run]
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
LOG_FILE="/var/log/stig_remediation.log"
DRY_RUN=false

# Parse command line arguments
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
    echo -e "${YELLOW}DRY RUN MODE - No changes will be made${NC}"
fi

# Function to log and display messages
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} $message"
            ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Function to backup a file before modification
backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        if [[ "$DRY_RUN" == "false" ]]; then
            cp "$file" "${file}.stig-backup-$(date +%Y%m%d-%H%M%S)"
            log_message "INFO" "Backed up $file"
        else
            log_message "INFO" "Would backup $file"
        fi
    fi
}

# Function to execute command with dry-run support
execute_command() {
    local cmd=$1
    local description=$2
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_message "INFO" "Would execute: $cmd ($description)"
    else
        log_message "INFO" "Executing: $description"
        if eval "$cmd"; then
            log_message "SUCCESS" "$description completed"
        else
            log_message "ERROR" "$description failed"
            return 1
        fi
    fi
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_message "ERROR" "This script must be run as root"
        exit 1
    fi
}

# Remediation: Set Boot Loader Password in grub2 (SV-271635r1091617_rule)
remediate_grub2_password() {
    log_message "INFO" "Remediating: Set Boot Loader Password in grub2"
    
    local grub_config="/etc/grub.d/01_users"
    
    if [[ "$DRY_RUN" == "false" ]]; then
        # Generate a password hash (you should change this password)
        local password="STIGCompliance123!"
        local password_hash=$(echo -e "$password\n$password" | grub2-mkpasswd-pbkdf2 | awk '/grub.pbkdf2/ {print $NF}')
        
        backup_file "$grub_config"
        
        cat > "$grub_config" << 'EOF'
#!/bin/sh -e
cat << ENDOF
set superusers="stig-admin"
password_pbkdf2 stig-admin HASH_PLACEHOLDER
ENDOF
EOF
        
        sed -i "s/HASH_PLACEHOLDER/$password_hash/" "$grub_config"
        chmod 755 "$grub_config"
        
        # Rebuild grub configuration
        grub2-mkconfig -o /boot/grub2/grub.cfg
        
        log_message "SUCCESS" "GRUB2 password set. Username: stig-admin, Password: $password"
        log_message "WARN" "Please change the default password after remediation"
    else
        log_message "INFO" "Would create GRUB2 password protection"
    fi
}

# Remediation: Set the Boot Loader Admin Username (SV-271451r1091065_rule) 
remediate_grub2_admin_username() {
    log_message "INFO" "Remediating: Set the Boot Loader Admin Username to a Non-Default Value"
    
    # This is handled in the grub2_password function above
    log_message "INFO" "Admin username will be set to 'stig-admin' with password protection"
}

# Remediation: Only Authorized Local User Accounts Exist (SV-271770r1092022_rule)
remediate_unauthorized_accounts() {
    log_message "INFO" "Remediating: Only Authorized Local User Accounts Exist on Operating System"
    
    # List accounts that might need review
    local system_accounts="root bin daemon adm lp sync shutdown halt mail operator games ftp nobody systemd-network dbus polkitd tss sssd rpc chrony"
    
    log_message "INFO" "Reviewing user accounts..."
    
    # Get all users with UID >= 1000 (typically regular users)
    local regular_users=$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd)
    
    if [[ -n "$regular_users" ]]; then
        log_message "WARN" "Found regular user accounts that may need review:"
        for user in $regular_users; do
            log_message "WARN" "  - $user"
        done
        log_message "INFO" "Manual review required: Ensure all regular user accounts are authorized"
        log_message "INFO" "To remove unauthorized accounts: userdel -r <username>"
    else
        log_message "SUCCESS" "No regular user accounts found to review"
    fi
}

# Remediation: Install and Configure FIPS
remediate_fips() {
    log_message "INFO" "Remediating: FIPS compliance (if applicable)"
    
    # Check if FIPS is required and not enabled
    if [[ ! -f /proc/sys/crypto/fips_enabled ]] || [[ "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0)" != "1" ]]; then
        log_message "WARN" "FIPS mode not enabled"
        log_message "INFO" "To enable FIPS mode:"
        log_message "INFO" "1. Install FIPS packages: dnf install dracut-fips"
        log_message "INFO" "2. Enable FIPS: fips-mode-setup --enable"
        log_message "INFO" "3. Reboot the system"
        log_message "WARN" "FIPS enablement requires manual intervention and system reboot"
    else
        log_message "SUCCESS" "FIPS mode already enabled"
    fi
}

# Remediation: Configure system settings that commonly fail
remediate_system_settings() {
    log_message "INFO" "Remediating: Common system configuration issues"
    
    # Set correct permissions on grub config
    if [[ -f /boot/grub2/grub.cfg ]]; then
        execute_command "chmod 600 /boot/grub2/grub.cfg" "Set GRUB2 config permissions"
        execute_command "chown root:root /boot/grub2/grub.cfg" "Set GRUB2 config ownership"
    fi
    
    # Ensure /tmp has correct mount options (if it's a separate filesystem)
    if mountpoint -q /tmp; then
        log_message "INFO" "/tmp is a separate mount point"
        # The mount options should be set in /etc/fstab for persistence
        log_message "INFO" "Verify /tmp mount options include: nodev,nosuid,noexec"
    fi
    
    # Set correct umask in multiple files
    local files_to_check=("/etc/bashrc" "/etc/profile" "/etc/csh.cshrc" "/etc/login.defs")
    
    for file in "${files_to_check[@]}"; do
        if [[ -f "$file" ]]; then
            backup_file "$file"
            
            case "$file" in
                "/etc/login.defs")
                    if ! grep -q "^UMASK[[:space:]]*077" "$file"; then
                        execute_command "sed -i 's/^UMASK.*/UMASK 077/' '$file'" "Set umask in $file"
                    fi
                    ;;
                *)
                    if ! grep -q "umask 077" "$file"; then
                        execute_command "echo 'umask 077' >> '$file'" "Add umask to $file"
                    fi
                    ;;
            esac
        fi
    done
}

# Remediation: Configure audit system
remediate_audit_system() {
    log_message "INFO" "Remediating: Audit system configuration"
    
    # Ensure auditd is installed and enabled
    execute_command "dnf install -y audit" "Install audit package"
    execute_command "systemctl enable auditd" "Enable auditd service"
    execute_command "systemctl start auditd" "Start auditd service"
    
    # Basic audit rules for STIG compliance
    local audit_rules="/etc/audit/rules.d/stig.rules"
    backup_file "$audit_rules"
    
    if [[ "$DRY_RUN" == "false" ]]; then
        cat > "$audit_rules" << 'EOF'
# STIG Audit Rules
# Monitor changes to system administration scope
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

# Monitor authentication files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity

# Monitor system startup scripts
-w /etc/rc.d/init.d/ -p wa -k init
-w /etc/init.d/ -p wa -k init

# Monitor library search paths
-w /etc/ld.so.conf -p wa -k libpath
-w /etc/ld.so.conf.d/ -p wa -k libpath

# Monitor kernel module loading and unloading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# Make the configuration immutable
-e 2
EOF
        
        systemctl restart auditd
        log_message "SUCCESS" "Audit rules configured"
    else
        log_message "INFO" "Would configure audit rules in $audit_rules"
    fi
}

# Remediation: Configure SSH settings
remediate_ssh_config() {
    log_message "INFO" "Remediating: SSH configuration"
    
    local sshd_config="/etc/ssh/sshd_config"
    backup_file "$sshd_config"
    
    # Common STIG SSH settings
    local ssh_settings=(
        "Protocol 2"
        "PermitRootLogin no"
        "PermitEmptyPasswords no"
        "ClientAliveInterval 600"
        "ClientAliveCountMax 0"
        "MaxAuthTries 3"
        "IgnoreRhosts yes"
        "HostbasedAuthentication no"
        "PermitUserEnvironment no"
        "Ciphers aes128-ctr,aes192-ctr,aes256-ctr"
        "MACs hmac-sha2-256,hmac-sha2-512"
    )
    
    for setting in "${ssh_settings[@]}"; do
        local key=$(echo "$setting" | cut -d' ' -f1)
        if [[ "$DRY_RUN" == "false" ]]; then
            # Remove existing setting and add new one
            sed -i "/^[#]*${key}/d" "$sshd_config"
            echo "$setting" >> "$sshd_config"
        else
            log_message "INFO" "Would set SSH: $setting"
        fi
    done
    
    execute_command "systemctl restart sshd" "Restart SSH daemon"
}

# Main execution
main() {
    log_message "INFO" "Starting Oracle Linux 9 STIG Remediation Script"
    log_message "INFO" "Log file: $LOG_FILE"
    
    check_root
    
    # Create log directory if it doesn't exist
    mkdir -p "$(dirname "$LOG_FILE")"
    
    echo "=== Oracle Linux 9 STIG Remediation Script ===" | tee "$LOG_FILE"
    echo "Started at: $(date)" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
    
    # High Priority Remediations (based on the report showing 2 high severity failures)
    log_message "INFO" "=== HIGH PRIORITY REMEDIATIONS ==="
    remediate_grub2_password
    remediate_grub2_admin_username
    
    # Medium Priority Remediations
    log_message "INFO" "=== MEDIUM PRIORITY REMEDIATIONS ==="
    remediate_unauthorized_accounts
    remediate_system_settings
    remediate_audit_system
    remediate_ssh_config
    
    # Additional checks
    log_message "INFO" "=== ADDITIONAL SECURITY CHECKS ==="
    remediate_fips
    
    echo ""
    log_message "SUCCESS" "STIG remediation script completed"
    log_message "INFO" "Please review the changes and reboot the system if required"
    log_message "INFO" "Run the OpenSCAP scan again to verify compliance improvements"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        echo ""
        log_message "YELLOW" "DRY RUN COMPLETED - No actual changes were made"
        log_message "INFO" "Review the proposed changes above, then run without --dry-run"
    fi
}

# Trap to ensure cleanup on exit
trap 'log_message "INFO" "Script execution finished"' EXIT

# Run main function
main "$@"