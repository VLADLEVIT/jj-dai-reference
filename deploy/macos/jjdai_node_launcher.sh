#!/bin/bash
# =============================================================================
# deploy/macos/jjdai_node_launcher.sh — launchd entrypoint for a JJ DAI node
# (v0.6.2, roadmap Ф0: macOS deployment kit)
# =============================================================================
# Invoked by org.jjdai.node.<name>.plist as the _jjdai role account.
# Responsibilities, in order:
#   1. load the node's env file (peers, anchors, rate limit — no secrets);
#   2. obtain JJDAI_KEYSTORE_PASSPHRASE from the System keychain
#      (deploy/macos/keychain_seal.py) — never from a file, never from
#      the plist; a documented env-file fallback exists for lab use only;
#   3. exec the daemon with the SAME flag set as the systemd unit, so the
#      two kits cannot drift apart silently (tests/unit/test_macos_kit.py
#      checks every flag below against node/daemon.py).
# -----------------------------------------------------------------------------
set -euo pipefail

NODE_NAME="${1:?usage: jjdai_node_launcher.sh <node-name>}"
ENV_FILE="${JJDAI_NODE_ENV:-/etc/jjdai/${NODE_NAME}.env}"

if [ -f "$ENV_FILE" ]; then
    # shellcheck disable=SC1090
    set -a; . "$ENV_FILE"; set +a
fi

# --- keystore passphrase: Keychain first, env-file fallback second -----------
if [ -z "${JJDAI_KEYSTORE_PASSPHRASE:-}" ]; then
    JJDAI_KEYSTORE_PASSPHRASE="$(/usr/bin/python3 \
        /opt/jjdai/deploy/macos/keychain_seal.py unseal \
        --node "${NODE_NAME}")" || {
        echo "no keystore passphrase: keychain unseal failed and none in" \
             "${ENV_FILE}; see RUNBOOK-macOS.md §2" >&2
        exit 1
    }
    export JJDAI_KEYSTORE_PASSPHRASE
fi
[ -n "${JJDAI_KEYSTORE_PASSPHRASE}" ] || {
    echo "empty keystore passphrase; refusing to start" >&2; exit 1; }

# --- exec the daemon (flag parity with deploy/jjdai-node@.service) -----------
exec /usr/bin/python3 -m node.daemon \
    --host 0.0.0.0 --port "${JJDAI_PORT:?set JJDAI_PORT in ${ENV_FILE}}" \
    --name "${NODE_NAME}" --fingerprint "${JJDAI_FINGERPRINT:?set JJDAI_FINGERPRINT}" \
    --node-keystore "/var/lib/jjdai/${NODE_NAME}.keystore" \
    --log "/var/lib/jjdai/${NODE_NAME}.jsonl" \
    --tls-cert "/etc/jjdai/pki/${NODE_NAME}.crt" \
    --tls-key "/etc/jjdai/pki/${NODE_NAME}.key" \
    --tls-ca /etc/jjdai/pki/ca.crt \
    --tls-require-client-cert \
    --peer-ca /etc/jjdai/pki/ca.crt \
    --client-cert "/etc/jjdai/pki/${NODE_NAME}.crt" \
    --client-key "/etc/jjdai/pki/${NODE_NAME}.key" \
    --authz-policy /etc/jjdai/authz.json \
    --revoked-serials @/etc/jjdai/pki/revoked.txt \
    --rate-limit "${JJDAI_RATE_LIMIT:-infer=30/60,task=10/60,write=60/60,read=120/60}" \
    --being-profile production \
    --being-provenance /etc/jjdai/provenance.json \
    --being-workspace "/var/lib/jjdai/${NODE_NAME}.ws" \
    --being-journals "/var/lib/jjdai/${NODE_NAME}.being" \
    --anchor-backends "${JJDAI_ANCHORS:-local}" \
    --peers "${JJDAI_PEERS:-}"
