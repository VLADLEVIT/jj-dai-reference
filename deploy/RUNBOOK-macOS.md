# JJ DAI testnet-0 — Operator Runbook, macOS node (v0.6.3)

Companion to `deploy/RUNBOOK.md` (Ubuntu). Everything not repeated here —
topology, PKI generation, authz policy, anchoring, DIVERGENCE_EVIDENCE
response, cert rotation/revocation — is identical and lives in the main
runbook. This file covers only what is DIFFERENT on the Mac node
(roadmap r5, Ф0: launchd instead of systemd, Keychain/Secure Enclave
instead of TPM, 24/7 power on a laptop chassis).

Target host: MacBook Pro, Apple Silicon, 128 GB unified memory / 2 TB —
the testnet-0 node that also carries inference (DeepSeek4Flash +
DwarfStar; DeepSeek4Pro in shadow mode only, per roadmap Ф1).

## 0. What maps to what

| Ubuntu node                       | macOS node                                      |
|-----------------------------------|-------------------------------------------------|
| `jjdai-node@.service` (systemd)   | `org.jjdai.node.<name>.plist` (launchd daemon)  |
| `deploy/tpm_seal.py` (TPM 2.0)    | `deploy/macos/keychain_seal.py` (System keychain)|
| `bootstrap_node.sh`               | `bootstrap_node_macos.sh`                       |
| `systemctl start/status`          | `launchctl bootstrap / kickstart / print`       |
| `journalctl -u`                   | `/var/lib/jjdai/log/<name>.{out,err}.log`       |
| `jjdai` system user               | `_jjdai` hidden role account (UID < 500)        |

PKI is generated once, on the same secured machine, with the same
`deploy/gen_pki.py` — the Mac node consumes leaf certs exactly like an
Ubuntu node.

## 1. Bootstrap

```
sudo NODE_NAME=ua-kyiv-1 PORT=8443 \
     FINGERPRINT="ua-kyiv-1:testnet-0" \
     PEERS="https://kr1.testnet.jj-dai.org:8443,https://ee1.testnet.jj-dai.org:8443" \
     ANCHORS="local,ots,xmr" \
     deploy/macos/bootstrap_node_macos.sh /path/to/checkout /path/to/pki
```

The script creates the hidden `_jjdai` role account, installs code to
`/opt/jjdai` (root:wheel, read-only for `_jjdai` — the daemon must
never own its own executable code, audit item #2), PKI to
`/etc/jjdai/pki`, writes the env file, renders and
lints the plist into `/Library/LaunchDaemons/`, and applies the 24/7
power profile. It never overwrites an existing keystore.

## 2. Keystore passphrase — the macOS Keychain degraded profile (non-SE-resident)

Preferred: seal into the **System** keychain (LaunchDaemons run
pre-login; user keychains are not available):

```
sudo python3 /opt/jjdai/deploy/macos/keychain_seal.py seal   --node ua-kyiv-1
sudo python3 /opt/jjdai/deploy/macos/keychain_seal.py status --node ua-kyiv-1
```

At boot the launcher unseals it and exports
`JJDAI_KEYSTORE_PASSPHRASE` into the daemon environment; the secret is
never present in the plist, the env file, or argv of the daemon.

**Stated, not hidden.** This is the **macOS Keychain degraded profile
(non-SE-resident)**: the `security` CLI stores a
keychain item, not a Secure-Enclave-resident key; the protection
boundary is the OS (Keychain ACL restricted to `/usr/bin/security`,
SIP, filesystem permissions), not the boot state. A TPM-sealed Ubuntu
node refuses to unseal on a tampered boot chain; a Mac node does not
have that property from the CLI. **The chosen profile is recorded in
the witness at bootstrap** — write it into your ops log and node
provenance so nobody ever thinks they have hardware protection they
don't. Lab-only fallback: `JJDAI_KEYSTORE_PASSPHRASE` in the 0640 env
file, exactly as on Ubuntu without a TPM.

A true **Secure Enclave-backed profile** (SE-resident key via
kSecAttrTokenIDSecureEnclave, API-only) is reserved as a separate future
attestation profile — it is NOT what this kit provides today, and no
document may imply otherwise.

### M-LIVE — operational evidence the unit tests do NOT prove

M-KIT/M-PLIST/M-FLAGS/M-SEC verify structure, syntax and flag parity.
The following must be demonstrated live on the target Mac and recorded
as evidence for the Ф0 target-host acceptance run (alongside S-1…S-5);
until each line is checked, the macOS kit counts as structurally, not
operationally, verified:

- [ ] LaunchDaemon under `_jjdai` obtains the passphrase from the
      System keychain **pre-login** (no user session).
- [ ] Node comes up cleanly after a **cold reboot**; keystore unseals;
      witness chain resumes without gaps.
- [ ] Keychain ACL actually admits the launcher path under this service
      account and denies an unlisted binary.
- [ ] FileVault on/off, an OS minor update, and a forced reboot do not
      break unseal.
- [ ] 72 h continuous run with `pmset -g log` showing **zero sleep
      events** and `/healthz` green throughout.

## 3. First start and the backup that must not be skipped

```
sudo launchctl bootstrap system /Library/LaunchDaemons/org.jjdai.node.ua-kyiv-1.plist
sudo launchctl kickstart -k system/org.jjdai.node.ua-kyiv-1
```

The FIRST start generates the identity keystore. **No further step —
not peers, not anchoring, not inference — until an offline backup of
`/var/lib/jjdai/<name>.keystore` is confirmed restored-readable.**
Identity is the keystore; losing it loses this node's identity forever
(rotation later requires the continuity-chain procedure, not a re-key).

## 4. Routine operations

```
sudo launchctl print system/org.jjdai.node.ua-kyiv-1     # status
sudo launchctl kickstart -k system/org.jjdai.node.ua-kyiv-1   # restart
sudo launchctl bootout system/org.jjdai.node.ua-kyiv-1   # stop/unload
tail -f /var/lib/jjdai/log/ua-kyiv-1.err.log             # logs
curl -sk https://127.0.0.1:8443/healthz                  # health
```

`KeepAlive` restarts the daemon on failure (ThrottleInterval 5 s) —
safe because the Witness is persist-before-expose and recovery is
journaled, same as on Ubuntu. `/metrics` is scraped identically.

## 5. Power: a laptop that must behave like a server

Applied by bootstrap, verify after every macOS update:

```
pmset -a sleep 0 disksleep 0 displaysleep 5
pmset -a powernap 0 standby 0 autopoweroff 0
pmset -a disablesleep 1        # keeps the node alive in clamshell
pmset -g                       # verify
```

* **Clamshell**: with `disablesleep 1` the node keeps running with the
  lid closed on battery or AC. If `disablesleep` is unavailable on your
  macOS build, clamshell requires AC power + external display, or
  `caffeinate -s` wrapped around the daemon — document whichever you
  use in the ops log.
* **UPS**: the Mac's internal battery is a built-in UPS for the host,
  but the router/switch it talks through is not — put the network path
  on the UPS too, or the node survives an outage mute.
* The Ф1 healthz gate requires **≥ 72 h green with no sleep gaps** —
  `pmset -g log | grep -i sleep` must show none.

## 6. What this host is NOT (read before trusting it)

* No systemd hardening parity: launchd provides no seccomp filter, no
  `MemoryDenyWriteExecute`, no `ProtectSystem=strict`. Isolation rests
  on the `_jjdai` role account, permissions, SIP and the Keychain ACL.
* Keystore protection is the macOS Keychain degraded profile (non-SE-resident) (§2), not
  TPM sealing — an attacker with root reads the passphrase.
* This node also carries the inference plane. Per roadmap Ф1, trust
  plane and inference run as SEPARATE processes and service identities
  with independent health checks; inference saturation or crash must
  never break witness replication, challenge participation, or keystore
  integrity. Until the dedicated inference launchd service lands, treat
  heavy inference load as an operational risk to watch on `/metrics`.
