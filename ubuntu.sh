#!/bin/bash
# ==============================================
# CIS Level 1 Hardening Script for Ubuntu 20.04 / 22.04 / 24.04 / 25.10
# Server-focused, Audit + Remediation
# ==============================================

set -euo pipefail
IFS=$'\n\t'

# -------------------------------
# Colors for output
# -------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${RED}[WARN]${NC} $1"; }

# -------------------------------
# Check OS
# -------------------------------
OS_ID=$(grep ^ID= /etc/os-release | cut -d= -f2 | tr -d '"')
OS_VERSION=$(grep ^VERSION_ID= /etc/os-release | cut -d= -f2 | tr -d '"')

if [[ "$OS_ID" != "ubuntu" ]]; then
    log_warn "This script is intended for Ubuntu 20.04/22.04/24.04/25.10 only. Detected: $OS_ID $OS_VERSION"
    exit 1
fi

log_info "Detected OS: $OS_ID $OS_VERSION"

# -------------------------------
# Ensure running as root
# -------------------------------
if [ "$EUID" -ne 0 ]; then
    log_warn "Please run as root"
    exit 1
fi

# -------------------------------
# Update and Install Essential Packages
# -------------------------------
log_info "Updating package lists and upgrading packages..."
apt update -y && apt upgrade -y

log_info "Installing CIS essential packages..."
PACKAGES="auditd ufw fail2ban apparmor apparmor-utils chrony pwquality"
apt install -y $PACKAGES

# -------------------------------
# 1. User and Authentication Hardening
# -------------------------------
log_info "Configuring password policies..."

# /etc/login.defs for aging
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs || echo "PASS_MAX_DAYS   90" >> /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs || echo "PASS_MIN_DAYS   7" >> /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs || echo "PASS_WARN_AGE   14" >> /etc/login.defs

# /etc/security/pwquality.conf
log_info "Setting password complexity..."
PWQUALITY="/etc/security/pwquality.conf"
cat <<EOT > "$PWQUALITY"
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOT

# PAM lockout (pam_faillock)
log_info "Configuring account lockout on failed logins..."
PAM_DIR="/etc/pam.d"
if ! grep -q "pam_faillock.so" "$PAM_DIR/common-auth"; then
    sed -i '/^auth\s\+required\s\+pam_unix.so/ i auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900' "$PAM_DIR/common-auth"
    sed -i '/^auth\s\+required\s\+pam_unix.so/ a auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900' "$PAM_DIR/common-auth"
fi
if ! grep -q "pam_faillock.so" "$PAM_DIR/common-account"; then
    echo "account required pam_faillock.so" >> "$PAM_DIR/common-account"
fi

log_ok "User and authentication hardening applied."

# -------------------------------
# 2. SSH Hardening
# -------------------------------
log_info "Auditing SSH configuration..."
SSHD_CONF="/etc/ssh/sshd_config"

declare -A ssh_settings=(
    ["PermitRootLogin"]="no"
    ["PasswordAuthentication"]="no"
    ["ChallengeResponseAuthentication"]="no"
    ["UsePAM"]="yes"
    ["X11Forwarding"]="no"
    ["MaxAuthTries"]="3"
    ["AllowTcpForwarding"]="no"
)

for key in "${!ssh_settings[@]}"; do
    if grep -q "^$key" "$SSHD_CONF"; then
        sed -i "s/^$key.*/$key ${ssh_settings[$key]}/" "$SSHD_CONF"
    else
        echo "$key ${ssh_settings[$key]}" >> "$SSHD_CONF"
    fi
done

systemctl restart sshd
log_ok "SSH hardening applied."

# -------------------------------
# 3. Firewall
# -------------------------------
log_info "Configuring UFW firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
log_ok "Firewall configured."

# -------------------------------
# 4. Services Hardening
# -------------------------------
log_info "Disabling unnecessary services..."
for svc in avahi-daemon cups snapd ModemManager; do
    if systemctl is-enabled "$svc" &>/dev/null; then
        systemctl disable --now "$svc"
        log_ok "Disabled $svc"
    fi
done

# -------------------------------
# 5. Kernel & Network Hardening
# -------------------------------
log_info "Applying sysctl hardening..."
SYSCTL_FILE="/etc/sysctl.d/99-cis.conf"
cat <<EOT > "$SYSCTL_FILE"
# IPv4
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# IPv6
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOT

sysctl --system
log_ok "Kernel and network hardening applied."

# -------------------------------
# 6. Mount Options
# -------------------------------
log_info "Enforcing mount options for /tmp, /var/tmp, /dev/shm..."
declare -A mounts=(
    ["/tmp"]="defaults,noexec,nosuid,nodev"
    ["/var/tmp"]="defaults,noexec,nosuid,nodev"
    ["/dev/shm"]="defaults,noexec,nosuid,nodev"
)

for mp in "${!mounts[@]}"; do
    if grep -q "$mp" /etc/fstab; then
        sed -i "s|^.*$mp.*|$mp ${mounts[$mp]} 0 0|" /etc/fstab
    else
        echo "$mp ${mounts[$mp]} 0 0" >> /etc/fstab
    fi
done
log_ok "Mount options enforced."

# -------------------------------
# 7. AppArmor
# -------------------------------
log_info "Enabling AppArmor and enforcing all profiles..."
systemctl enable --now apparmor
aa-status | grep -q "profiles are in enforce mode"
if [ $? -ne 0 ]; then
    for profile in /etc/apparmor.d/*; do
        aa-enforce "$profile" 2>/dev/null || true
    done
fi
log_ok "AppArmor enforcement applied."

# -------------------------------
# 8. Auditing
# -------------------------------
log_info "Applying auditd rules..."
AUDIT_RULES_FILE="/etc/audit/rules.d/cis.rules"
cat <<EOT > "$AUDIT_RULES_FILE"
# Login and Authentication Events
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Sudo
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# Login/logout events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.* -p wa -k cron
-w /etc/at.allow -p wa -k cron
-w /etc/at.deny -p wa -k cron

# Kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
EOT

systemctl restart auditd
log_ok "Audit rules applied."

# -------------------------------
# 9. Login Banners
# -------------------------------
log_info "Setting login banners..."
cat <<EOT > /etc/motd
Authorized users only. All activity may be monitored and reported.
EOT
chmod 644 /etc/motd
log_ok "Login banners applied."

# -------------------------------
# 10. NTP / Time Sync
# -------------------------------
log_info "Ensuring time synchronization..."

# Enable chrony
systemctl enable --now chronyd
timedatectl set-ntp true

# Backup default chrony config
CHRONY_CONF="/etc/chrony/chrony.conf"
if [ ! -f "${CHRONY_CONF}.bak" ]; then
    cp "$CHRONY_CONF" "${CHRONY_CONF}.bak"
fi

# Replace NTP servers with only 192.168.200.2
sed -i '/^pool /d' "$CHRONY_CONF"
sed -i '/^server /d' "$CHRONY_CONF"
echo "server 192.168.200.2 iburst" >> "$CHRONY_CONF"

# Restart chrony to apply
systemctl restart chronyd
chronyc sources -v
log_ok "Time synchronization configured."

# -------------------------------
# Final Message
# -------------------------------
log_ok "CIS Level 1 Hardening Audit + Remediation Completed for Ubuntu $OS_VERSION."
log_info "Review logs above for any warnings or failures."

exit 0
