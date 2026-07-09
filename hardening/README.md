# Hardening Pass — What Was Added, and What's Actually Verified

This documents the security-hardening additions on top of the base honeypot
suite (see the top-level `README.md` for the original platform). Every item
below is labeled with its actual verification status — that label is the
most important part of this document. Claiming something works without
having run it is worse than not having it.

## ✅ Tested end-to-end in this build session

| File | What was verified |
|---|---|
| `deploy/systemd/*.service`, `*.target` | `systemd-analyze verify` — clean on all 6 units after fixing a misplaced `StartLimitIntervalSec`/`StartLimitBurst` (belongs in `[Unit]`, not `[Service]` — caught by the verifier, not by inspection) |
| `deploy/iptables/honeypot-egress.sh` | `bash -n` / `sh -n` syntax check |
| `deploy/seccomp/honeypot-seccomp.json`, all K8s manifests, `monitoring/grafana/honeypot-dashboard.json` | Parsed as valid JSON/YAML against documented schemas |
| `hardening/vault_commands.sh`, `hardening/s3_worm_archive.sh` | `bash -n` syntax check; runs cleanly (prints documented commands, makes no live Vault/AWS calls) |
| `hardening/sign_release.sh` | **Full live test**: generated a real ephemeral GPG keypair, signed a file, verified the signature (good), then tampered with the file and re-verified (correctly reported BAD signature, exit code 1) |
| `hardening/tarpit.py` | **Full live test**: real `paramiko` SSH client against the actual patched `ssh_honeypot.py` — confirmed via log output that the tarpit engages exactly at the configured failure threshold (not before), holds the connection for the configured delay, and resets cleanly. 7 dedicated pytest tests added (`tests/test_core.py::TestTarpit`), including one that measures real wall-clock sleep time, not just the bookkeeping state. |
| `hardening/auto_analyze_malware.py` (YARA stage) | **Full live test**: ran against a real PHP webshell payload (correctly flagged CRITICAL) and a clean text file (correctly flagged no match); `--sweep` mode tested against a populated `malware/samples/` directory |
| `hardening/auto_analyze_malware.py` (Cuckoo stage) | **Failure-path tested**: pointed at an unreachable endpoint, confirmed it logs a warning and returns `None` instead of raising — the capture pipeline degrades to YARA-only instead of crashing. The actual submission code follows Cuckoo's documented REST API but was never exercised against a live Cuckoo server (none available in this environment). |
| `bandit` SAST findings | Ran against the full codebase: found 3 real HIGH-severity findings (MD5/SHA1 usage in `malware_capture.py` and `http_honeypot.py`), confirmed they were false positives in context (hash-based malware fingerprinting, not security/integrity use), and fixed them properly with `usedforsecurity=False` rather than suppressing the warning — re-ran bandit to confirm 0 HIGH findings remain |
| `pip-audit` against `requirements.txt` | Ran — "No known vulnerabilities found" as of this session |
| `config.yaml` → `alert_system.py` wiring | Proved the new `alerting.brute_force_threshold` config key is genuinely live-read (not coincidentally matching the old hardcoded default) by changing it to a different value and confirming `alert_system.BRUTE_THRESHOLD` picked up the change |
| All 36 `pytest` tests | Pass after every change in this pass (29 from the prior session + 7 new tarpit tests) |

## ⚠️ Reviewed for correctness, NOT executed against live infrastructure

No Kubernetes cluster, Vault server, AWS account, Elasticsearch/Logstash
instance, Suricata install, Grafana instance, Cuckoo Sandbox, or Terraform
binary exists in this build environment (network egress here is allowlisted
to pypi/npm/github only). Everything below was written to documented
schemas/API references and checked for internal consistency, but treat it
as **reviewed boilerplate, not verified-working configuration** until you've
run it against your actual infrastructure:

- `deploy/docker/docker-compose.hardened.yml` — valid Compose v3.9 syntax;
  the network segmentation model (`internal: true` honeypot-net + a
  separate `egress-allow` network for the one service that needs it) is
  standard Docker practice, but the whole file has never been
  `docker-compose up`'d in this environment.
- `deploy/k8s/*.yaml` — valid YAML against the NetworkPolicy v1 /
  Deployment / RBAC schemas, but NetworkPolicy is a no-op unless your CNI
  plugin enforces it (Calico/Cilium do; the default kubenet does not) —
  verify that before relying on the deny-all-egress policy.
- `deploy/terraform/security_group.tf`, `deploy/terraform/iam.tf` — HCL
  reviewed for standard `aws_security_group`/`aws_iam_role` resource
  syntax (brace/quote balance checked programmatically), but
  `terraform validate` was never run — no `terraform` binary or AWS
  provider access here. Run `terraform fmt -check && terraform validate`
  yourself before `terraform plan`.
- `monitoring/filebeat/filebeat.yml`, `monitoring/logstash/honeypot-pipeline.conf`
  — standard Filebeat/Logstash config DSL, not run through
  `filebeat test config` or `logstash --config.test_and_exit`.
- `monitoring/suricata/honeypot.rules` — standard Suricata 7.x rule
  syntax, not run through `suricata -T`.
- `hardening/s3_worm_archive.sh` — the AWS CLI commands are syntactically
  correct and the Object Lock COMPLIANCE-mode logic is accurate (Object
  Lock can only be set at bucket creation, COMPLIANCE mode blocks even the
  root account), but never run against a real AWS account.

## What changed in the existing (non-hardening) codebase

Two small, behavior-preserving edits to the original honeypot files:

1. **`alert_system.py`** — `BRUTE_THRESHOLD`/`BRUTE_WINDOW` were hardcoded
   constants; now read from `config.yaml`'s new `alerting.brute_force_*`
   keys, falling back to the exact same values (5, 120) if config is
   unavailable. No behavior change unless you edit config.yaml.
2. **`http_honeypot.py`, `malware_capture.py`** — added
   `usedforsecurity=False` to the MD5/SHA1 calls used for malware-sample
   fingerprinting, per the bandit findings above. No functional change —
   same hash output, same hex digest, just explicit about non-security
   intent so the linter (and future readers) don't have to guess.

Everything else in this hardening pass is purely additive — new files
under `deploy/`, `hardening/`, `monitoring/`, none of the original
honeypot listener logic (`ssh_honeypot.py`, `http_honeypot.py`,
`ftp_honeypot.py`, `decoy_services.py`) was rewritten, only the tarpit
hook patched in externally from `run.py`, same pattern as the existing
logger/alert_system/mitre_attack patches.

## Quick reference: what to run first

```bash
# Verify the hardening additions didn't break anything
pytest tests/ -v

# See the tarpit actually engage (fast, no real network needed)
python hardening/tarpit.py

# See YARA catch a real webshell payload
python hardening/auto_analyze_malware.py --sweep

# Lint for security issues (should show 0 HIGH after this pass's fixes)
bandit -r . -x ./tests,./yara_rules,./malware/samples

# Dependency CVE check
pip-audit -r requirements.txt
```
