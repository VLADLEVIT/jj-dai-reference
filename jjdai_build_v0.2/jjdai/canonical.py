# -*- coding: utf-8 -*-
"""
jjdai.canonical — RFC 8785 JSON Canonicalization Scheme (JCS).

Deterministic byte encoding so independent nodes hash identical payloads
identically. Used by the witness chain, commitments, and content-addressing.

  * object keys sorted by UTF-16 code units (RFC 8785 §3.2.3)
  * strings escaped minimally (RFC 8259 / ECMAScript JSON.stringify)
  * numbers via ECMAScript Number::toString (RFC 8785 §3.2.2.3)

Documented limitation (prototype scope): the ES6 number serializer below is
faithful for integers, integer-valued floats (0.0→"0", 1.0→"1"), and normal
decimals — i.e. everything in JJ DAI payloads (sampling, scores). Very small
magnitudes in the 1e-6..1e-4 band and extreme exponents are NOT yet matched to
ES6 exactly; validate against a JCS conformance vector set before production,
and keep consensus-critical numbers integer / simple-decimal.
"""

import re

def _es6_number(n) -> str:
    if isinstance(n, bool):
        raise TypeError("bool is not a JSON number")
    if isinstance(n, int):
        return str(n)
    f = float(n)
    if f != f or f in (float("inf"), float("-inf")):
        raise ValueError("non-finite numbers are not permitted in JCS")
    if f == 0.0:
        return "0"                          # also normalises -0.0
    if f.is_integer() and abs(f) < 1e21:
        return str(int(f))                  # 1.0 -> "1", 42.0 -> "42"
    r = repr(f)                             # shortest round-trip decimal
    m = re.match(r"^(-?)(\d+)(?:\.(\d+))?[eE]([+-]?\d+)$", r)
    if m:
        sign, intp, frac, exp = m.groups()
        exp = int(exp)
        mant = intp + ("." + frac if frac else "")
        esign = "+" if exp >= 0 else "-"
        return f"{sign}{mant}e{esign}{abs(exp)}"
    return r


def _escape_string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o == 0x08:
            out.append("\\b")
        elif o == 0x09:
            out.append("\\t")
        elif o == 0x0A:
            out.append("\\n")
        elif o == 0x0C:
            out.append("\\f")
        elif o == 0x0D:
            out.append("\\r")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)                  # literal UTF-8, incl. non-ASCII
    out.append('"')
    return "".join(out)


def _key_sort(key: str):
    # RFC 8785 sorts by UTF-16 code units.
    return key.encode("utf-16-be")


def _serialize(obj) -> str:
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, str):
        return _escape_string(obj)
    if isinstance(obj, (int, float)):
        return _es6_number(obj)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_serialize(x) for x in obj) + "]"
    if isinstance(obj, dict):
        items = sorted(obj.items(), key=lambda kv: _key_sort(kv[0]))
        return "{" + ",".join(_escape_string(k) + ":" + _serialize(v)
                              for k, v in items) + "}"
    raise TypeError(f"not JCS-serializable: {type(obj).__name__}")


def canonical(obj) -> bytes:
    """Return the RFC 8785 canonical UTF-8 byte encoding of a JSON value."""
    return _serialize(obj).encode("utf-8")
