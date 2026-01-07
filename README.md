# Guest Hardening Scripts
These scripts are designed to harden Debian-based systems by applying various security best practices. The following systems have been verified to work.
- Debian (12 and 13)
- Ubuntu (22.04, 24.04, and 25.10)

## Key Features

- Updates the system and ensures it's running the latest packages.
- Configures ufw to manage firewall rules.
- Hardens SSH by disabling root login and password authentication.
- Enforces strong password policies and limits authentication attempts.
- Installs and configures fail2ban.
- Disables unused services to reduce attack surface.
- Configures kernel parameters for additional security.
- Sets up automatic updates for critical patches.
- Uses Lynis to audit system at the end.

## Caution
This script makes significant changes to your system's configuration. Make sure to review the script and test it in a non-production environment before using it on production systems.

## How to Use the Script

1. Clone the scripts: ```git clone https://github.com/JeuTheIdit/guest-hardening```.
2. Make the script executable: ```chmod +x debian_hardening.sh``` or ```chmod +x ubuntu_hardening.sh```
3. Run the script with root privileges: ```sudo ./debian_hardening.sh``` or ```sudo ./ubuntu_hardening.sh```
