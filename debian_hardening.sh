#!/bin/bash

set -e

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

echo "Starting Debian 12 hardening process..."

# Logging setup
LOGFILE="/var/log/debian_hardening.log"
exec > >(tee -a "$LOGFILE") 2>&1

# Update and upgrade system packages
echo "Updating and upgrading system..."
apt update && apt upgrade -y

# Install essential security tools
echo "Installing essential security tools..."
apt install -y ufw fail2ban unattended-upgrades auditd lynis apparmor apparmor-profiles apparmor-utils

# Configure automatic security updates
echo "Configuring unattended upgrades..."
echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections
DEBIAN_FRONTEND=noninteractive apt install -y unattended-upgrades

# Configure UFW firewall
echo "Configuring UFW firewall..."
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
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOT
chmod 600 /etc/fail2ban/jail.local
systemctl enable fail2ban --now

# Enable auditd
echo "Enabling auditd..."
systemctl enable auditd
systemctl start auditd

# Disable unneeded services
echo "Disabling unnecessary services..."
systemctl stop avahi-daemon cups
systemctl disable avahi-daemon cups

# Optional: disable Bluetooth
# systemctl disable bluetooth

# Harden kernel parameters
echo "Applying sysctl kernel hardening..."
cat <<EOT > /etc/sysctl.d/99-hardening.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
kernel.randomize_va_space = 2
EOT
chmod 600 /etc/sysctl.d/99-hardening.conf
sysctl --system

# Secure home directory permissions
echo "Securing /home directories..."
chmod 750 /home/* 2>/dev/null || true

# Mount /tmp with noexec,nosuid,nodev
echo "Securing /tmp..."
cat <<EOT > /etc/systemd/system/tmp.mount
[Unit]
Description=Temporary Directory
Before=local-fs.target

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,noexec,nosuid,nodev

[Install]
WantedBy=local-fs.target
EOT
systemctl daemon-reexec
systemctl enable tmp.mount
systemctl start tmp.mount

# Enable AppArmor
echo "Enabling AppArmor..."
systemctl enable apparmor
systemctl start apparmor

# Set MOTD warning banner
echo "Setting login warning banner..."
cat <<EOT > /etc/motd
** WARNING **
This system is for authorized users only. All activity is monitored and logged.
EOT

# Basic security audit
echo "Running security audit with Lynis..."
lynis audit system

# Optional manual checks
echo "Checking for world-writable files..."
find / -xdev -type f -perm -0002 -print 2>/dev/null

echo "Checking for SUID files..."
find / -xdev -type f -perm -4000 -print 2>/dev/null

echo ""
echo "Debian 12 hardening complete. See log: $LOGFILE"
