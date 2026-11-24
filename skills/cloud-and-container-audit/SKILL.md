---
name: cloud-and-container-audit
description: Playbook for auditing cloud accounts (AWS/Azure/GCP) and container/supply-chain surfaces with the BEHEMOTH arsenal — aws/az/gcloud recon, Pacu privilege-escalation, Scout Suite audits, and trivy/grype image scanning plus semgrep source review.
---

# Cloud & Container Audit Playbook

Use this skill when an engagement covers cloud accounts (AWS/Azure/GCP), container images/registries, Docker daemons, or source repositories.

## 1. Cloud Account Discovery (AWS)
1. **Identity & Posture**: Start read-only with `run_security_tool` (`aws-recon`) → `sts get-caller-identity` to fingerprint the account, then enumerate regions, IAM users/roles/policies (`iam list-users`, `iam list-roles`), and exposure-prone services (`s3 ls`, `ec2 describe-instances` with public IPs, `rds` snapshots, `lambda list-functions`).
2. **Privilege Escalation**: Import credentials into **Pacu** (`pacu-recon`) and run `iam__enum_users_roles_policies`, `iam__privesc_scan`, `ec2__enum`. Report exploitable trust relationships and inline-policy escalations.
3. **Deep Audit**: With valid credentials, run **Scout Suite** (`scout-suite`) against the provider/profile and attach the HTML report path to the finding.
4. **Azure/GCP**: `az-recon` (`account show`, `resource list`) and `gcloud-recon` (`projects list`, `iam policies`) when those CLIs are installed and authenticated; skip gracefully if `list_security_arsenal` reports them missing.

## 2. Container & Supply-Chain Scanning
1. **Image Scanning**: `run_security_tool` (`trivy-scan`, mode `image`) or `grype-scan` on discovered image references (from `docker ps`, compose files, CI configs). Record CRITICAL/HIGH CVEs with fixed versions.
2. **Docker Socket Exposure**: If 2375/2376 is reachable, enumerate images/containers/mounts via `curl --unix-socket` or the Docker API over HTTP; test for privileged containers and host mounts (`/:host`).
3. **Filesystem/Repo Mode**: Use `trivy-scan` mode `fs` on any workspace checkout or artifact bundle before deeper SAST.

## 3. Source Review (SAST)
1. Run `semgrep-scan` (config `auto`, or `p/owasp-top-ten`, `p/secrets`) against the target's source tree when available.
2. Correlate secret findings with the Intelligence tab and `record_intelligence`; correlate injection findings with web test results before `report_finding`.

## 4. Reporting Rules
- Always include the account/project ID (masked where needed), the exact CLI command or image digest, and structured JSON/text output evidence.
- Bind cloud-hygiene findings (public buckets, wildcard IAM actions, exposed management ports) and container CVEs as separate findings with concrete remediation (policy/least-privilege fix or patched image tag).
