# JJ DAI testnet-0 — Operator Runbook (v0.6.3)

> **macOS node?** This runbook targets Ubuntu 24. The Mac node (launchd,
> Keychain sealing, 24/7 power on a laptop chassis) is covered by
> `deploy/RUNBOOK-macOS.md`; PKI, authz, anchoring and incident response
> are shared and live here.

This is the operational companion to the reference codebase. It assumes
Ubuntu 24.04 with `systemd`, `python3` (≥3.10), and `openssl`. Nothing
here needs third-party Python packages — the node core is stdlib-only.

The guiding rule of this network: **a node's identity is its keystore.**
Lose the keystore and you lose that node's place in the witness fabric
forever. Everything below is arranged so that never happens by accident.

---

## 0. Topology

testnet-0 is three nodes in three jurisdictions — UA (Kyiv), KR (via the
Korean partners), EE (an EU point) — chosen so the verifier panels have
real operator-domain and jurisdiction diversity. Each node runs the
production Being profile, so every task is independently verified or
refused. Any two nodes form a replication quorum for the third.

---

## 1. Build the PKI (once, on a secured machine)

The root CA key is the crown jewel; it never needs to touch a node.

    python3 deploy/gen_pki.py init-ca --out pki --cn "JJ DAI testnet-0 Root"

    # one leaf per node — SANs must match how peers dial it:
    python3 deploy/gen_pki.py node --out pki --name ua-kyiv-1 \
        --dns ua1.testnet.jj-dai.org --ip <public-ip>
    python3 deploy/gen_pki.py node --out pki --name kr-seoul-1 \
        --dns kr1.testnet.jj-dai.org --ip <public-ip>
    python3 deploy/gen_pki.py node --out pki --name ee-tallinn-1 \
        --dns ee1.testnet.jj-dai.org --ip <public-ip>

    # one admin client cert per operator (CN must appear in authz.json):
    python3 deploy/gen_pki.py admin --out pki --cn ops-ua

After issuing, **move `pki/ca.key` to cold storage.** Nodes need only
`ca.crt` and their own leaf. `pki/serials.tsv` is your issuance ledger.

Place `authz.json` (start from `deploy/authz.testnet.json`) and the
fleet `provenance.json` beside the PKI so bootstrap can install them.

---

## 2. Bootstrap each node

Copy the checkout + that node's PKI material to the host, then:

    sudo NODE_NAME=ua-kyiv-1 PORT=8443 \
         FINGERPRINT="ua-kyiv-1:testnet-0" \
         PEERS="https://kr1.testnet.jj-dai.org:8443,https://ee1.testnet.jj-dai.org:8443" \
         ANCHORS="local,ots,xmr" \
         deploy/bootstrap_node.sh /path/to/checkout /path/to/pki

This creates the `jjdai` system user and lays out the ownership model
(audit item #2 — the daemon must never own its own executable code):

    /opt/jjdai       root:root      code, read-only for the daemon
    /etc/jjdai       root:jjdai     policies and PKI
    /var/lib/jjdai   jjdai:jjdai    witness, journals, replicas, workspace

It lays out `/opt/jjdai`,
`/var/lib/jjdai`, `/etc/jjdai`, installs the hardened
`jjdai-node@.service`, and writes `/etc/jjdai/<node>.env`.

### Keystore passphrase — three options

* **TPM-sealed (preferred, Ubuntu).** On a TPM 2.0 host:

      sudo apt install tpm2-tools
      sudo python3 deploy/tpm_seal.py seal --out /var/lib/jjdai/sealed
      # then in <node>.env, the unit unseals at boot; nothing plaintext on disk

* **System keychain (macOS node).** `deploy/macos/keychain_seal.py seal
  --node <name>` — the documented macOS Keychain degraded profile (non-SE-resident); see
  `RUNBOOK-macOS.md` §2 for what it does and does not protect.

* **Env file (fallback).** Append `JJDAI_KEYSTORE_PASSPHRASE=...` to
  `/etc/jjdai/<node>.env` (0640, root:jjdai). Record that you did this.

---

## 3. First start and the backup that must not be skipped

    sudo systemctl start jjdai-node@ua-kyiv-1
    # the FIRST start generates the identity keystore. Back it up NOW:
    sudo cp /var/lib/jjdai/ua-kyiv-1.keystore  <offline-encrypted-backup>
    sudo systemctl enable jjdai-node@ua-kyiv-1

Read the node id and record it in your peers manifest:

    curl --cacert /etc/jjdai/pki/ca.crt \
         --cert pki/admin-ops-ua.crt --key pki/admin-ops-ua.key \
         https://127.0.0.1:8443/capabilities | python3 -m json.tool

---

## 4. Health and observability

* `GET /healthz` — open; returns uptime, node id, record count.
* `GET /metrics` — Prometheus text (peer/admin cert required):
  `jjdai_requests_total`, `jjdai_denied_authz_total`,
  `jjdai_rate_limited_total`, `jjdai_revoked_rejected_total`,
  `jjdai_witness_records`, `jjdai_tasks_total`,
  `jjdai_challenge_rounds_total`, `jjdai_uptime_seconds`.
* `journalctl -u jjdai-node@<node> -f` for the process log.

A rising `denied_authz_total` or `rate_limited_total` is your early
signal of a misconfigured peer or an abusive client. A rising
`revoked_rejected_total` means a revoked cert is still trying.

---

## 5. Routine operations

### Add a node
Issue its leaf (step 1), bootstrap it (step 2), start + back up (step 3),
then add its `https://…` to every existing node's `JJDAI_PEERS` and
restart them one at a time. Admission beyond transport is the steward
flow (peers registry); transport is what this step wires.

### Rotate / revoke a compromised cert
    python3 deploy/gen_pki.py revoke --out pki --serial <hex-serial>
    # push the updated pki/revoked.txt to every node, then:
    sudo systemctl restart jjdai-node@<node>       # reloads --revoked-serials
The revoked cert is 401 on every path immediately after restart.

### Restart / recover a node
Restart is safe: the Witness is persist-before-expose and the Being
runtime journals its lifecycle, so a restart resumes semantic state and
resolves any in-flight task honestly (FAILED, or FATE_UNKNOWN for an
action whose outcome the crash hid). If the disk is intact, just
`systemctl restart`. If the disk is lost but you kept the keystore
backup and at least two peers are healthy, restore from the keystore and
let segment recovery pull the chain back against the quorum-anchored
root.

### Respond to DIVERGENCE_EVIDENCE
If a node witnesses divergence (a peer presenting two inconsistent signed
roots), that evidence is durable and self-proving. Do not "fix" it by
deleting logs. Capture the evidence, take the implicated node out of the
peers set, and review before re-admitting — equivocation is exactly what
the fabric is built to make undeniable.

---

## 6. Anchoring

* `local` — always on; receipts in `<log>.anchors.jsonl`.
* `ots` — needs `--ots-calendar <url>`; Bitcoin-depth proof (slow anchor).
* `xmr` — needs `--xmr-wallet-rpc <url>` and a wallet holding **anchoring
  dust only**; fast anchor (2-min blocks). Budget ≈ a couple of XMR per
  node per decade at the hourly rhythm; the hierarchy makes it per-network,
  not per-node.

Verify anchoring is live: `GET /witness/anchors` lists held receipts.

---

## 7. What this release is NOT

testnet-0 on v0.5.5 is a security-**alpha**: authorization, rate
limiting, revocation, production PKI, metrics and the networked challenge
round are real, but Karma remains a reference sandbox (not hardened
isolation), the knowledge store is retrieval-baseline (not a knowledge
graph), and DIIP is deliberately absent. Do not run untrusted workloads
against `/v1/tasks`, and keep the peers set to operators you know.
Jai Guru Dev.
