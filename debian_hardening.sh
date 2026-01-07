#!/bin/bash

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging functions
msg_info()    { echo -e "${YELLOW}INFO:${NC} $1"; }
msg_ok() { echo -e "${GREEN}SUCCESS:${NC} $1"; }
msg_error()   { echo -e "${RED}ERROR:${NC} $1"; }

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    msg_error "Please run as root"
    exit 1
fi

msg_info "Starting Debian 12 hardening process..."

# Logging setup
LOGFILE="/var/log/debian_hardening.log"
exec > >(tee -a "$LOGFILE") 2>&1

# Update and upgrade system packages
msg_info "Updating and upgrading system..."
apt update && apt upgrade -y

# Install essential security tools
msg_info "Installing essential security tools..."
apt install -y ufw fail2ban unattended-upgrades auditd audispd-plugins lynis apparmor apparmor-profiles apparmor-utils

# Configure automatic security updates
msg_info "Configuring unattended upgrades..."
systemctl enable --now unattended-upgrades

# Configure UFW firewall
msg_info "Configuring UFW firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow ssh
ufw limit ssh comment 'Limit SSH connection attempts'
ufw enable

# Check for at least one user with SSH key access before disabling password logins
echo "Checking for SSH access for non-root users..."
skip_ssh_hardening=false
user_with_key=$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | while read user; do
    if [ -f "/home/$user/.ssh/authorized_keys" ]; then echo $user; break; fi
done)

if [ -z "$user_with_key" ]; then
    echo "WARNING: No non-root users with SSH keys found. Skipping SSH PasswordAuthentication hardening to prevent lockout."
    skip_ssh_hardening=true
fi

# Function to safely update SSH config
update_ssh_config() {
    local option="$1"
    local value="$2"
    local config_file="/etc/ssh/sshd_config"

    if [ ! -f "$config_file.bak" ]; then
        cp "$config_file" "$config_file.bak"
        echo "Backup of sshd_config created at $config_file.bak"
    fi

    if grep -q "^#\?\s*$option" "$config_file"; then
        sed -i -E "s/^#?\s*($option).*/\1 $value/" "$config_file"
        echo "$option set to $value in $config_file"
    else
        echo "$option $value" >> "$config_file"
        echo "$option added with value $value"
    fi
}

# Harden SSH
if [ "$skip_ssh_hardening" != true ]; then
    echo "Hardening SSH..."
    update_ssh_config "PermitRootLogin" "no"
    update_ssh_config "PasswordAuthentication" "no"
    update_ssh_config "X11Forwarding" "no"
    update_ssh_config "MaxAuthTries" "3"
    update_ssh_config "StrictModes" "yes"
    update_ssh_config "AllowUsers" "jnbolsen"
    systemctl restart sshd
else
    echo "SSH hardening skipped to avoid lockout."
fi

# Configure password policies
echo "Setting password policies..."
if [ -f /etc/security/pwquality.conf ]; then
    cp /etc/security/pwquality.conf /etc/security/pwquality.conf.bak
fi

cat <<EOT > /etc/security/pwquality.conf
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOT
chmod 600 /etc/security/pwquality.conf

# Enforce account lockout after failed login attempts
echo "auth required pam_tally2.so deny=5 unlock_time=900" >> /etc/pam.d/common-auth

# Configure Fail2Ban
echo "Configuring Fail2Ban..."
if [ -f /etc/fail2ban/jail.local ]; then
    cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
fi

cat <<EOT > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 8h

[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOT
chmod 600 /etc/fail2ban/jail.local
systemctl enable --now fail2ban

# Enable auditd
echo "Enabling auditd..."
systemctl enable --now auditd

# Function to remove services and packages
remove_service_and_package() {
    local svc="$1"
    local pkg="$2"

    if systemctl list-unit-files | grep -q "^${svc}"; then
        msg_info "Disabling and stopping ${svc}"
        systemctl disable --now "${svc}" &>/dev/null
    fi

    if dpkg -s "${pkg}" &>/dev/null; then
        msg_info "Removing package ${pkg}"
        apt purge -y "${pkg}"
    else
        msg_info "Package ${pkg} not installed, skipping"
    fi
}

# Remove Avahi
remove_service_and_package "avahi-daemon.service" "avahi-daemon"

# Remove CUPS (printing system)
remove_service_and_package "cups.service" "cups"

# Remove ModemManager (mobile broadband daemon)
remove_service_and_package "ModemManager.service" "modemmanager"

# Remove Snap only if no essential snaps are installed
if snap list &>/dev/null && [ "$(snap list | wc -l)" -le 1 ]; then
    remove_service_and_package "snapd.service" "snapd" "Snap (snapd service)"
else
    msg_info "Snap packages detected, skipping removal to avoid breaking snaps"
fi

# Cleanup unused dependencies
msg_info "Running apt autoremove"
apt autoremove -y

# Optional: disable Bluetooth
# systemctl disable bluetooth

# Harden kernel parameters
msg_info "Applying sysctl kernel hardening..."
cat <<EOT > /etc/sysctl.d/99-hardening.conf
# Disable IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0

# ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# TCP SYN flood protection
net.ipv4.tcp_syncookies = 1

# Address Space Layout Randomization (ASLR)
kernel.randomize_va_space = 2

# Reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log suspicious/misrouted packets (martians)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ICMP broadcast protection (smurf attacks)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable TCP timestamps to reduce fingerprinting
net.ipv4.tcp_timestamps = 0
EOT
chmod 600 /etc/sysctl.d/99-hardening.conf
sysctl --system

# Function to add a mount to fstab if not already present
add_mount() {
    local line="$1"
    local mount_point
    mount_point=$(echo "$line" | awk '{print $2}')
    
    if grep -q "[[:space:]]$mount_point[[:space:]]" "$FSTAB"; then
        echo "Mount for $mount_point already exists in fstab. Skipping..."
    else
        echo "$line" >> "$FSTAB"
        echo "Added mount for $mount_point"
    fi
}

# Add noexec, nosuid, and nodev to /tmp, /var/tmp, and /dev/shm mounts
add_mount "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0"
add_mount "tmpfs /var/tmp tmpfs defaults,noexec,nosuid,nodev 0 0"
add_mount "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0"
mount -a

# Enable AppArmor
msg_info "Enabling AppArmor..."
systemctl enable --now apparmor

# Set MOTD warning banner
msg_info "Setting login warning banner..."
cat <<EOT > /etc/motd
** WARNING **
This system is for authorized users only. All activity is monitored and logged.
EOT

# Basic security audit
msg_info "Running security audit with Lynis..."
lynis audit system

# Optional manual checks
msg_info "Checking for world-writable files..."
find / -xdev -type f -perm -0002 -print 2>/dev/null

msg_info "Checking for SUID files..."
find / -xdev -type f -perm -4000 -print 2>/dev/null

msg_info ""
msg_ok "Debian 12 hardening complete. See log: $LOGFILE"
