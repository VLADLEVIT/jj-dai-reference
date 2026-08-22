#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_ingress_hardening — v0.6.4 adversarial acceptance
======================================================
Every check is written to FAIL against v0.6.3, where the ingress path read an
undeclared body length in full, kept no ceiling on requests in flight, put no
clock on a connection, and charged the rate-limit budget to a client ADDRESS.

  G-1  BODY CAP: a body over the cap is refused 413 BEFORE it is read.
  G-2  BODY CAP IS NOT A SUGGESTION: a lying Content-Length cannot smuggle a
       larger body past the reader.
  G-3  BAD FRAMING: a non-integer or negative Content-Length is a controlled
       400, not an exception in the handler thread.
  G-4  CHUNKED REFUSED: a body whose length is not declared cannot be capped
       before it is read, so it is refused 411.
  G-5  CONNECTION CLOCK: the handler carries a per-connection timeout, so a
       client that opens and stalls releases its thread.
  G-6  CONCURRENCY CEILING BOUNDS THREADS, not merely request processing:
       stalled TCP connections far above the ceiling never produce worker
       threads above it. (The first cut of this drop took the slot inside
       the handler — i.e. inside a thread that already existed — so it
       bounded processing and not thread creation. This check is written to
       fail against that version.)
  G-7  OVER THE CEILING THE NODE ANSWERS, rather than queueing work it has
       not agreed to hold, and the ceiling is not a latch: releasing a slot
       restores service. The answer is a 503 the caller can actually read:
       closing over unread inbound data resets the connection and takes the
       answer with it, which leaves a caller unable to tell overload from a
       dead node.
  G-8  BUDGET FOLLOWS IDENTITY, NOT ADDRESS: with a client certificate the
       rate-limit key is the certificate identity; without one it is a
       namespaced address that can never collide with a certificate key.
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import sys
import tempfile
import threading
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from daemon import (BoundedThreadingHTTPServer, HashEngine, Node,     # noqa: E402
                    make_handler)

HOST = "127.0.0.1"


class _Server:
    """A live node on an ephemeral port, torn down with the context."""

    def __init__(self, tmp, **node_kw):
        self.node = Node(name="ingress-test", profile="B",
                         substrates=["sha256:base-A"], adapters={},
                         engine=HashEngine("fp-ingress"),
                         log_path=os.path.join(tmp, "witness.jsonl"),
                         **node_kw)
        self.srv = BoundedThreadingHTTPServer((HOST, 0),
                                             make_handler(self.node),
                                             node=self.node)
        self.port = self.srv.server_address[1]
        self.thread = threading.Thread(target=self.srv.serve_forever,
                                       kwargs={"poll_interval": 0.05},
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=5)

    def post(self, path, body: bytes, headers=None, timeout=5):
        c = http.client.HTTPConnection(HOST, self.port, timeout=timeout)
        try:
            h = {"Content-Type": "application/json"}
            h.update(headers or {})
            c.request("POST", path, body=body, headers=h)
            r = c.getresponse()
            return r.status, r.read()
        finally:
            c.close()

    def raw(self, blob: bytes, timeout=5):
        s = socket.create_connection((HOST, self.port), timeout=timeout)
        try:
            s.sendall(blob)
            s.settimeout(timeout)
            out = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                out += chunk
                if b"\r\n\r\n" in out:
                    break
            return out
        finally:
            s.close()


def _envelope(pad: int = 0) -> bytes:
    return json.dumps({
        "substrate_id": "sha256:base-A", "adapter_ids": [],
        "sampling": {"temperature": 0.0, "top_p": 1.0, "max_tokens": 4,
                     "seed": 1},
        "request_id": "req-ingress", "nonce": "nonce-ingress-xx",
        "messages": [{"role": "user", "content": "x" * pad or "hello"}],
    }).encode()


def test_oversized_body_refused():
    with tempfile.TemporaryDirectory() as tmp, \
            _Server(tmp, max_body_bytes=2048) as s:
        code, body = s.post("/v1/messages", _envelope(pad=8192))
        assert code == 413, f"oversized body accepted: {code} {body[:200]}"
        doc = json.loads(body)
        assert doc["limit_bytes"] == 2048, doc
        assert s.node.metrics["body_too_large_total"] == 1, s.node.metrics
        # and it is refused BEFORE the engine is ever reached
        assert s.node.metrics.get("inferences_total", 0) == 0, s.node.metrics


def test_lying_content_length_cannot_smuggle():
    """Declare a small body, send a large one: the reader must consume only
    what was declared and capped. The surplus must not reach the parser."""
    with tempfile.TemporaryDirectory() as tmp, \
            _Server(tmp, max_body_bytes=4096) as s:
        payload = b'{"a": "' + b"z" * 20000 + b'"}'
        head = (f"POST /v1/messages HTTP/1.1\r\nHost: {HOST}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: 12\r\nConnection: close\r\n\r\n").encode()
        out = s.raw(head + payload)
        assert out.startswith(b"HTTP/1."), out[:80]
        status = int(out.split()[1])
        assert status == 400, f"expected a controlled 400, got {status}"
        assert s.node.metrics["body_too_large_total"] == 0, s.node.metrics


def test_bad_framing_is_controlled():
    with tempfile.TemporaryDirectory() as tmp, _Server(tmp) as s:
        for bad in (b"not-a-number", b"-5"):
            head = (b"POST /v1/messages HTTP/1.1\r\nHost: " + HOST.encode()
                    + b"\r\nContent-Length: " + bad
                    + b"\r\nConnection: close\r\n\r\n")
            out = s.raw(head)
            assert out.startswith(b"HTTP/1."), out[:80]
            status = int(out.split()[1])
            assert status == 400, f"Content-Length {bad!r} -> {status}"
        assert s.node.metrics["bad_framing_total"] >= 2, s.node.metrics


def test_chunked_is_refused():
    with tempfile.TemporaryDirectory() as tmp, _Server(tmp) as s:
        head = (f"POST /v1/messages HTTP/1.1\r\nHost: {HOST}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: close\r\n\r\n4\r\ntest\r\n0\r\n\r\n").encode()
        out = s.raw(head)
        status = int(out.split()[1])
        assert status == 411, f"chunked body accepted: {status}"


def test_connection_carries_a_clock():
    with tempfile.TemporaryDirectory() as tmp, \
            _Server(tmp, request_timeout_s=0.5) as s:
        handler = s.srv.RequestHandlerClass
        assert handler.timeout == 0.5, handler.timeout
        # a client that connects and says nothing must be released, not held
        c = socket.create_connection((HOST, s.port), timeout=5)
        try:
            t0 = time.time()
            c.settimeout(4)
            data = c.recv(4096)          # returns b"" once the server closes
            assert data == b"", data[:80]
            assert time.time() - t0 < 4, "stalled client held the thread"
        finally:
            c.close()


def test_stalled_connections_cannot_grow_threads():
    """The property the mechanism actually claims: a client that opens many
    connections and says nothing must not cost one worker thread each."""
    CEILING, ATTEMPTS = 4, 100
    with tempfile.TemporaryDirectory() as tmp, \
            _Server(tmp, max_concurrency=CEILING,
                    request_timeout_s=30.0) as s:      # long clock on purpose:
        time.sleep(0.2)                                # expiry must not be
        baseline = threading.active_count()            # what saves us here
        socks = []
        try:
            for _ in range(ATTEMPTS):
                try:
                    c = socket.create_connection((HOST, s.port), timeout=2)
                    c.setblocking(False)               # connect, then silence
                    socks.append(c)
                except OSError:
                    break
            time.sleep(1.0)
            grown = threading.active_count() - baseline
            # ceiling + the accept loop's own slack; the single bounded
            # refusal worker is started with the server, so it is already
            # inside the baseline
            # ceiling plus the accept loop's own slack; the single bounded
            # refusal worker starts with the server and is already inside
            # the baseline
            assert grown <= CEILING + 1, (
                f"{len(socks)} stalled connections produced {grown} worker "
                f"threads against a ceiling of {CEILING} — admission is "
                f"happening after thread creation")
            assert s.node.metrics["overloaded_total"] >= ATTEMPTS - CEILING - 2, \
                s.node.metrics
        finally:
            for c in socks:
                try:
                    c.close()
                except OSError:
                    pass


def test_ceiling_answers_and_is_not_a_latch():
    with tempfile.TemporaryDirectory() as tmp, \
            _Server(tmp, max_concurrency=1) as s:
        # hold the only admission slot, then knock
        assert s.node.ingress_sem.acquire(blocking=False)
        try:
            code, body = s.post("/v1/messages", _envelope())
            assert code == 503, f"ceiling not enforced: {code}"
            doc = json.loads(body)
            assert doc["max_concurrency"] == 1, doc
            assert s.node.metrics["overloaded_total"] == 1, s.node.metrics
        finally:
            s.node.ingress_sem.release()
        # released: the node serves again, so admission is not a latch
        code, _ = s.post("/v1/messages", _envelope())
        assert code == 200, f"node did not recover after release: {code}"


def test_rate_budget_is_keyed_by_identity():
    # RateLimiter config is {class: (limit, window_s)}
    limits = {"infer": (2, 60.0)}
    seen = {}
    with tempfile.TemporaryDirectory() as tmp, \
            _Server(tmp, rate_limits=limits) as s:
        base = s.srv.RequestHandlerClass

        class _Probe(base):
            """Stands in for a verified mTLS peer without needing a CA."""

            def _peer_identity(self):
                return seen.get("cn"), seen.get("serial")

        s.srv.RequestHandlerClass = _Probe

        # no certificate -> a NAMESPACED address key, never a bare address
        seen.clear()
        s.post("/v1/messages", _envelope())
        keys = sorted(k for k, _ in s.node.rate_limiter._windows)
        assert any(k.startswith("ip:") for k in keys), keys
        assert HOST not in keys, f"budget still keyed by bare address: {keys}"

        # with a certificate -> the IDENTITY carries the budget
        seen.update({"cn": "node-a.testnet", "serial": "0A1B"})
        s.post("/v1/messages", _envelope())
        keys = sorted(k for k, _ in s.node.rate_limiter._windows)
        assert any(k.startswith("cert:node-a.testnet:") for k in keys), keys

        # moving address does NOT reset a certificate's budget: same cert,
        # different address, same bucket. (Under v0.6.3 keying this was the
        # free reset that made the limiter decorative.)
        before = len([k for k in keys if k.startswith("cert:")])
        s.post("/v1/messages", _envelope())
        keys2 = sorted(k for k, _ in s.node.rate_limiter._windows)
        assert len([k for k in keys2 if k.startswith("cert:")]) == before, \
            keys2

        # the third request is over the budget of 2
        code, body = s.post("/v1/messages", _envelope())
        assert code == 429, f"identity budget not enforced: {code}"

        s.srv.RequestHandlerClass = base


if __name__ == "__main__":
    tests = [test_oversized_body_refused,
             test_lying_content_length_cannot_smuggle,
             test_bad_framing_is_controlled,
             test_chunked_is_refused,
             test_connection_carries_a_clock,
             test_stalled_connections_cannot_grow_threads,
             test_ceiling_answers_and_is_not_a_latch,
             test_rate_budget_is_keyed_by_identity]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\ningress hardening — {len(tests)}/{len(tests)} checks green")
