# GPU host for hash cracking (DigitalOcean)

Cracking is the one workload in BEHEMOTH where CPU alone cannot keep up: a
rockyou-sized run against bcrypt/NTLM takes hours on vCPU and minutes on a
single modern GPU. This document covers picking a GPU droplet, migrating to it
without changing the public IP, and wiring the GPU into the agent.

## 1. What the codebase already has (and what it does not)

Already wired:

- `setup.sh` installs **hashcat** and **john** (`install_security_arsenal`), and
  the JWT skill tells the agent to use them on `HS256` secrets.
- `sandbox_exec` runs cracking in a throwaway container (`agent/sandbox.go`).

Gaps a GPU host exposes — now handled by `./setup.sh gpu` and
`BEHEMOTH_SANDBOX_GPUS`:

- The OpenCL runtime was `pocl-opencl-icd` (CPU only): needs the NVIDIA driver's
  ICD instead.
- The distro `john` package is CPU-only non-jumbo: we install a **`john-jumbo`**
  build (`/usr/local/bin/john-jumbo`) with OpenCL formats.
- `sandbox_exec` had no `--gpus` flag: set `BEHEMOTH_SANDBOX_GPUS=all` to pass
  the device through (requires the NVIDIA container toolkit).

`hashcat` remains the preferred tool on GPU (far better multi-GPU and rule/mask
throughput); `john-jumbo` is for formats hashcat lacks and for hash *identify*
workflows via `john --list=formats`.

## 2. Droplet choice

GPU droplets **cannot be reached by resizing** the current droplet — you create
a new one and move to it. Pick the class by workload:

| Use | Droplet | Notes |
|---|---|---|
| **Recommended** | **1× RTX 6000 Ada (48 GB)** with 16 vCPU / 64 GB RAM / 500 GB NVMe | Highest SM count and clocks of the workstation cards; 48 GB VRAM holds large mask/wordlist sessions plus a parallel john job. Host RAM must cover pg + agent + a 1–2 GB mask file orbited in memory |
| **Parallel jobs / heavier** | **2× RTX 6000 Ada** or **L40S (1–2×, 48 GB)** | hashcat scales ~linearly per GPU; L40S is datacenter-cooled and better on FP16 |
| **Future LLM inference alongside cracking** | **1× H100 80 GB (or 2×)** | Best FP16/BF16 and vLLM throughput, so it doubles as a local model host; overkill for cracking alone |

Guardrails:

- GPU droplets bill by the hour (roughly $1.5–5/hour for the classes above), so
  put a schedule on it (`doctl compute droplet-action power-off`) or power it off
  between engagements; keep the disk and data on a **Volume** so it survives.
- Cracking needs a **CPU with headroom**: hashcat's brain/queue kernels and
  `--wordlist` streaming starve on 2 vCPU. Never pick a GPU plan below 8 vCPU.
- Prefer a GPU flavor in a region that also hosts your Volumes and Reserved IP,
  and note DO's GPU regions currently exclude SFO2 in most accounts.

## 3. Migration runbook (keeps the public IP, no service gap until cutover)

The IP lives on the droplet, so the trick is a **Reserved IP** that you move at
cutover, with short DNS TTL beforehand.

1. **Lower TTL** on the `A` record to 60 s and wait out the old TTL (DNS TTL
   only matters if you land in another region and must re-point).
2. **Freeze a copy of the data**: `pg_dumpall` plus `tar` of the app directory
   (`/opt/behemoth`, workspace, wordlists, potfiles) to object storage.
   Take a droplet snapshot too — it is the rollback path.
3. **Create the GPU droplet** in the same region (Ubuntu 24.04 GPU image, or
   stock Ubuntu + `./setup.sh gpu`). Do not install the app by hand: run
   `./setup.sh full`, then restore the dump and the tarball over it.
4. **Reserve a Reserved IP** and assign it to the **new** droplet
   (`doctl compute reserved-ip create --region <region>` /
   `doctl compute reserved-ip-action assign <ip> <new-droplet-id>`).
   Assigning moves it off the old droplet; the address itself does not change.
5. **Verify on the new host** before switching traffic: `nvidia-smi`,
   `hashcat -I` (must list a CUDA/OpenCL device), `clinfo`, then log in to the UI
   on the Reserved IP and run one `sandbox_exec` with `nvidia-smi`.
6. **Switch DNS** to the Reserved IP if the region changed, then confirm the
   site and an agent run.
7. **Retire** the old droplet after 24–48 h of green monitoring (keep its
   snapshot), and raise the TTL back.

Services stay up throughout: steps 1–5 happen on the new host while the old one
serves traffic; the only swap is the IP/DNS cutover, which is seconds.

## 4. Wiring the GPU in

```bash
sudo BEHEMOTH_GPU=1 ./setup.sh gpu     # driver, ICD, container toolkit, hashcat, john-jumbo
hashcat -I && john-jumbo --list=opencl-devices
```

Then set on the agent process:

```bash
BEHEMOTH_SANDBOX_GPUS=all
```

Restart BEHEMOTH. `sandbox_exec` now passes `--gpus all`, so the agent can run
`hashcat`/`john-jumbo` inside the sandbox (mount a cracking image that ships the
binaries, or `apt-get install -y hashcat` in the container) and the host stays
clean.

Give the agent a hint in the task prompt: hash mode first
(`hashcat --identify <hash>` / `john --list=formats`), then a rules pass, then a
mask pass — and cap `--runtime` so a session does not hang the task.
