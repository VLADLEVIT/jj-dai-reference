# Observability — scraping a JJ DAI node (v0.6.6)

`/metrics` is Prometheus text exposition and is **not anonymous**: the authz
policy allows `peer` and `admin`. A scraper therefore needs a client
certificate, exactly like any other peer. This is deliberate — the metric set
names loaded engines, broken toolsets and anchoring lag, which together are a
usable map for choosing where to push.

```yaml
scrape_configs:
  - job_name: jjdai-node
    scheme: https
    metrics_path: /metrics
    scrape_interval: 15s
    tls_config:
      ca_file:   /etc/jjdai/pki/ca.crt
      cert_file: /etc/jjdai/pki/prom.crt      # gen_pki.py peer --cn prom
      key_file:  /etc/jjdai/pki/prom.key
    static_configs:
      - targets: ['ua.testnet.jj-dai.org:8443',
                  'kr.testnet.jj-dai.org:8443',
                  'ee.testnet.jj-dai.org:8443']
```

Rules: `jjdai-alerts.yml` in this directory.

## The three health surfaces, and what each answers

| Endpoint | Question | Role |
|---|---|---|
| `/healthz` | is this process running and able to form a reply | anonymous |
| `/readyz` | should work be sent here | peer, admin |
| `/metrics` | how is it behaving over time | peer, admin |

A liveness answer read as permission to send work is the failure this split
exists to prevent. `/readyz` returns **503** when the aggregate is red, so an
orchestrator that only looks at the status code still behaves correctly
without parsing the body.

## Readiness gauges

One numeric scale for every subsystem, so no alert rule ever has to join two
metrics to learn one fact:

    1    ready
    0.5  degraded — functioning below policy, still serving
    0    not ready
    -1   not configured on this node — never a fault

`jjdai_ready` is the aggregate. It is red only for **core** subsystems
(identity, witness, anchoring). Engine, isolation and being degrade the node
without removing it from the network: a node whose wasm toolset is
unprovisioned is still a full witness participant, and this build ships no
compiled wasm modules at all, so any other choice would report every fresh
node as unready.

## What is deliberately NOT here

No dashboards-as-code beyond the starter in `../grafana/`, and no recording
rules. Both encode SLO target values, and r6.6.2 assigns SLO owners in Ф0
while leaving the values TBD until the end of Ф3. Shipping thresholds now
would mean shipping guesses with the authority of a config file.
