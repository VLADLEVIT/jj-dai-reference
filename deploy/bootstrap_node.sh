#!/usr/bin/env bash
# =============================================================================
# deploy/bootstrap_node.sh — bring up one JJ DAI testnet-0 node on Ubuntu 24
# =============================================================================
# Idempotent where it can be. Run as root on the target host AFTER you have:
#   * the node's leaf cert/key + ca.crt (from deploy/gen_pki.py), and
#   * the fleet provenance.json + authz.json.
#
#   sudo NODE_NAME=ua-kyiv-1 PORT=8443 \
#        FINGERPRINT="ua-kyiv-1:testnet-0" \
#        PEERS="https://kr1.testnet.jj-dai.org:8443,https://ee1.testnet.jj-dai.org:8443" \
#        ANCHORS="local,ots,xmr" \
#        deploy/bootstrap_node.sh /path/to/checkout /path/to/pki
#
# It will NOT overwrite an existing keystore (identity is sacred). It
# prints the node_id at the end — record it in your peers manifest.
# -----------------------------------------------------------------------------
set -euo pipefail

CHECKOUT="${1:?usage: bootstrap_node.sh <checkout-dir> <pki-dir>}"
PKI="${2:?usage: bootstrap_node.sh <checkout-dir> <pki-dir>}"
NODE_NAME="${NODE_NAME:?set NODE_NAME}"
PORT="${PORT:-8443}"
FINGERPRINT="${FINGERPRINT:-${NODE_NAME}:testnet-0}"
PEERS="${PEERS:-}"
ANCHORS="${ANCHORS:-local}"
RATE_LIMIT="${RATE_LIMIT:-infer=30/60,task=10/60,write=60/60,read=120/60}"

echo "==> creating jjdai user + directories"
id -u jjdai >/dev/null 2>&1 || useradd --system --home /opt/jjdai \
    --shell /usr/sbin/nologin jjdai
install -d -o jjdai -g jjdai -m 0755 /opt/jjdai /var/lib/jjdai
install -d -o root  -g jjdai -m 0750 /etc/jjdai /etc/jjdai/pki

echo "==> installing code to /opt/jjdai"
cp -r "$CHECKOUT"/. /opt/jjdai/
chown -R jjdai:jjdai /opt/jjdai

echo "==> installing PKI material (leaf key stays 0640 root:jjdai)"
install -o root -g jjdai -m 0644 "$PKI/ca.crt"            /etc/jjdai/pki/ca.crt
install -o root -g jjdai -m 0644 "$PKI/${NODE_NAME}.crt"  /etc/jjdai/pki/${NODE_NAME}.crt
install -o root -g jjdai -m 0640 "$PKI/${NODE_NAME}.key"  /etc/jjdai/pki/${NODE_NAME}.key
touch /etc/jjdai/pki/revoked.txt
[ -f "$PKI/revoked.txt" ] && install -o root -g jjdai -m 0644 "$PKI/revoked.txt" /etc/jjdai/pki/revoked.txt
chown root:jjdai /etc/jjdai/pki/revoked.txt; chmod 0644 /etc/jjdai/pki/revoked.txt

echo "==> installing policy + provenance (must already exist beside PKI)"
install -o root -g jjdai -m 0644 "$PKI/authz.json"        /etc/jjdai/authz.json
install -o root -g jjdai -m 0644 "$PKI/provenance.json"   /etc/jjdai/provenance.json

echo "==> writing /etc/jjdai/${NODE_NAME}.env"
cat > /etc/jjdai/${NODE_NAME}.env <<EOF
JJDAI_PORT=${PORT}
JJDAI_FINGERPRINT=${FINGERPRINT}
JJDAI_PEERS=${PEERS}
JJDAI_ANCHORS=${ANCHORS}
JJDAI_RATE_LIMIT=${RATE_LIMIT}
# Keystore passphrase: prefer TPM sealing (deploy/tpm_seal.py). For a
# non-TPM host, append a line below (this file is 0640 root:jjdai) and
# document it in your ops log:
#   JJDAI_KEYSTORE_PASSPHRASE=...
EOF
chown root:jjdai /etc/jjdai/${NODE_NAME}.env
chmod 0640 /etc/jjdai/${NODE_NAME}.env

echo "==> installing systemd unit"
install -m 0644 /opt/jjdai/deploy/jjdai-node@.service \
    /etc/systemd/system/jjdai-node@.service
systemctl daemon-reload

cat <<NEXT

==> node scaffolding ready for '${NODE_NAME}'.

   Before first start:
   1) provide the keystore passphrase (TPM-sealed or in the env file);
   2) the FIRST start generates the identity keystore — back it up
      immediately (losing it loses this node's identity forever):
        sudo systemctl start jjdai-node@${NODE_NAME}
        sudo cp /var/lib/jjdai/${NODE_NAME}.keystore  <secure-backup>
   3) enable on boot:
        sudo systemctl enable jjdai-node@${NODE_NAME}
   4) read the node_id and add it to your peers manifest:
        curl --cacert /etc/jjdai/pki/ca.crt \\
             --cert /etc/jjdai/pki/admin-*.crt --key ... \\
             https://127.0.0.1:${PORT}/capabilities | jq .node_id

   Health: curl -sk https://127.0.0.1:${PORT}/healthz
   Metrics: scrape https://127.0.0.1:${PORT}/metrics (peer/admin cert)
NEXT
