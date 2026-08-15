#!/bin/bash
# =============================================================================
# deploy/macos/bootstrap_node_macos.sh — bring up one JJ DAI testnet-0 node
# on macOS (Apple Silicon) · v0.6.2 · roadmap Ф0: macOS deployment kit
# =============================================================================
# Mirrors deploy/bootstrap_node.sh (Ubuntu). Idempotent where it can be.
# Run as root on the target Mac AFTER you have:
#   * the node's leaf cert/key + ca.crt (from deploy/gen_pki.py), and
#   * the fleet provenance.json + authz.json.
#
#   sudo NODE_NAME=ua-kyiv-1 PORT=8443 \
#        FINGERPRINT="ua-kyiv-1:testnet-0" \
#        PEERS="https://kr1.testnet.jj-dai.org:8443,https://ee1.testnet.jj-dai.org:8443" \
#        ANCHORS="local,ots,xmr" \
#        deploy/macos/bootstrap_node_macos.sh /path/to/checkout /path/to/pki
#
# It will NOT overwrite an existing keystore (identity is sacred). It
# prints next steps at the end — including the un-skippable keystore backup.
# -----------------------------------------------------------------------------
set -euo pipefail

CHECKOUT="${1:?usage: bootstrap_node_macos.sh <checkout-dir> <pki-dir>}"
PKI="${2:?usage: bootstrap_node_macos.sh <checkout-dir> <pki-dir>}"
NODE_NAME="${NODE_NAME:?set NODE_NAME}"
case "$NODE_NAME" in
  (*[!a-z0-9-]*|-*|*-)
    echo "NODE_NAME '$NODE_NAME' invalid: lowercase a-z, 0-9 and '-' only," \
         "must not start or end with '-'" >&2; exit 1;;
esac
PORT="${PORT:-8443}"
FINGERPRINT="${FINGERPRINT:-${NODE_NAME}:testnet-0}"
PEERS="${PEERS:-}"
ANCHORS="${ANCHORS:-local}"
RATE_LIMIT="${RATE_LIMIT:-infer=30/60,task=10/60,write=60/60,read=120/60}"

JJDAI_UID="${JJDAI_UID:-399}"   # <500 keeps the account out of login windows

echo "==> creating _jjdai role account + directories"
# UID/GID collision guard: refuse to reuse an ID owned by someone else.
if EXIST_UID_USER="$(dscl . -search /Users UniqueID "${JJDAI_UID}" \
      | awk 'NR==1{print $1}')" && [ -n "$EXIST_UID_USER" ] \
      && [ "$EXIST_UID_USER" != "_jjdai" ]; then
    echo "UID ${JJDAI_UID} already taken by '$EXIST_UID_USER' —" \
         "set JJDAI_UID to a free id (<500)" >&2; exit 1
fi
if EXIST_GID_GRP="$(dscl . -search /Groups PrimaryGroupID "${JJDAI_UID}" \
      | awk 'NR==1{print $1}')" && [ -n "$EXIST_GID_GRP" ] \
      && [ "$EXIST_GID_GRP" != "_jjdai" ]; then
    echo "GID ${JJDAI_UID} already taken by group '$EXIST_GID_GRP' —" \
         "set JJDAI_UID to a free id (<500)" >&2; exit 1
fi
# group BEFORE user, so PrimaryGroupID always resolves
if ! dscl . -read /Groups/_jjdai >/dev/null 2>&1; then
    dscl . -create /Groups/_jjdai
    dscl . -create /Groups/_jjdai PrimaryGroupID "${JJDAI_UID}"
fi
if ! dscl . -read /Users/_jjdai >/dev/null 2>&1; then
    dscl . -create /Users/_jjdai
    dscl . -create /Users/_jjdai UserShell /usr/bin/false
    dscl . -create /Users/_jjdai UniqueID "${JJDAI_UID}"
    dscl . -create /Users/_jjdai PrimaryGroupID "${JJDAI_UID}"
    dscl . -create /Users/_jjdai NFSHomeDirectory /var/empty
    dscl . -create /Users/_jjdai RealName "JJ DAI trust node"
    dscl . -create /Users/_jjdai IsHidden 1
fi

install -d -o root   -g wheel  -m 0755 /opt/jjdai
install -d -o _jjdai -g _jjdai -m 0755 /var/lib/jjdai
install -d -o _jjdai -g _jjdai -m 0755 /var/lib/jjdai/log
install -d -o root   -g _jjdai -m 0750 /etc/jjdai /etc/jjdai/pki

echo "==> installing code to /opt/jjdai (root-owned: the daemon must NOT"
echo "    be able to modify its own executable code — audit item #2)"
cp -R "$CHECKOUT"/. /opt/jjdai/
chown -R root:wheel /opt/jjdai
find /opt/jjdai -type d -exec chmod 0755 {} \;
find /opt/jjdai -type f -exec chmod 0644 {} \;
chmod 0755 /opt/jjdai/deploy/macos/jjdai_node_launcher.sh \
           /opt/jjdai/deploy/macos/bootstrap_node_macos.sh

echo "==> installing PKI material (leaf key stays 0640 root:_jjdai)"
install -o root -g _jjdai -m 0644 "$PKI/ca.crt"            /etc/jjdai/pki/ca.crt
install -o root -g _jjdai -m 0644 "$PKI/${NODE_NAME}.crt"  "/etc/jjdai/pki/${NODE_NAME}.crt"
install -o root -g _jjdai -m 0640 "$PKI/${NODE_NAME}.key"  "/etc/jjdai/pki/${NODE_NAME}.key"
touch /etc/jjdai/pki/revoked.txt
[ -f "$PKI/revoked.txt" ] && install -o root -g _jjdai -m 0644 "$PKI/revoked.txt" /etc/jjdai/pki/revoked.txt
chown root:_jjdai /etc/jjdai/pki/revoked.txt; chmod 0644 /etc/jjdai/pki/revoked.txt

echo "==> installing policy + provenance (must already exist beside PKI)"
install -o root -g _jjdai -m 0644 "$PKI/authz.json"        /etc/jjdai/authz.json
install -o root -g _jjdai -m 0644 "$PKI/provenance.json"   /etc/jjdai/provenance.json

echo "==> writing /etc/jjdai/${NODE_NAME}.env"
cat > "/etc/jjdai/${NODE_NAME}.env" <<EOF
JJDAI_PORT=${PORT}
JJDAI_FINGERPRINT=${FINGERPRINT}
JJDAI_PEERS=${PEERS}
JJDAI_ANCHORS=${ANCHORS}
JJDAI_RATE_LIMIT=${RATE_LIMIT}
# Keystore passphrase: prefer the System keychain (deploy/macos/
# keychain_seal.py seal --node ${NODE_NAME}) — the documented
# macOS Keychain degraded profile (non-SE-resident). For a lab host ONLY, append a line
# below (this file is 0640 root:_jjdai) and record it in your ops log:
#   JJDAI_KEYSTORE_PASSPHRASE=...
EOF
chown root:_jjdai "/etc/jjdai/${NODE_NAME}.env"
chmod 0640 "/etc/jjdai/${NODE_NAME}.env"

echo "==> installing launchd daemon"
PLIST="/Library/LaunchDaemons/org.jjdai.node.${NODE_NAME}.plist"
sed "s/__NODE_NAME__/${NODE_NAME}/g" \
    /opt/jjdai/deploy/macos/org.jjdai.node.plist > "$PLIST"
chown root:wheel "$PLIST"; chmod 0644 "$PLIST"
plutil -lint "$PLIST"

echo "==> 24/7 power profile (trust node must not sleep)"
pmset -a sleep 0 disksleep 0 displaysleep 5
pmset -a powernap 0 standby 0 autopoweroff 0 || true
pmset -a disablesleep 1 || echo "   (disablesleep unsupported here — verify clamshell behavior manually, see RUNBOOK-macOS.md §5)"

cat <<NEXT

==> node scaffolding ready for '${NODE_NAME}'.

   Before first start:
   1) seal the keystore passphrase into the System keychain:
        sudo python3 /opt/jjdai/deploy/macos/keychain_seal.py seal --node ${NODE_NAME}
   2) load the daemon (first start generates the identity keystore):
        sudo launchctl bootstrap system ${PLIST}
        sudo launchctl kickstart -k system/org.jjdai.node.${NODE_NAME}
   3) back the keystore up IMMEDIATELY (losing it loses this node's
      identity forever — no further step until the backup is confirmed):
        sudo cp /var/lib/jjdai/${NODE_NAME}.keystore  <secure-offline-backup>
   4) read the node_id and add it to your peers manifest:
        curl --cacert /etc/jjdai/pki/ca.crt \\
             --cert /etc/jjdai/pki/admin-*.crt --key ... \\
             https://127.0.0.1:${PORT}/capabilities | jq .node_id

   Health:  curl -sk https://127.0.0.1:${PORT}/healthz
   Metrics: scrape https://127.0.0.1:${PORT}/metrics (peer/admin cert)
   Status:  sudo launchctl print system/org.jjdai.node.${NODE_NAME}
NEXT
