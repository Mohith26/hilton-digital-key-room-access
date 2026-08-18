"""Prove the offline verifier truly needs no DB and no network.

Two independent proofs:
  1. STATIC: the transitive import closure of `staykey.lock` (+ credential +
     antireplay) contains no database, socket, HTTP, or web-framework module.
  2. FUNCTIONAL: a LockVerifier is constructed from ONLY (property_pub, revocation
     set) and makes correct unlock/deny decisions with sqlite3.connect and
     socket.socket monkeypatched to raise if touched.
"""

from __future__ import annotations

import importlib
import socket
import sqlite3
import sys

import pytest

from staykey import credential
from staykey.lock import LockVerifier

FORBIDDEN = {
    "sqlite3", "socket", "http", "httpx", "requests", "urllib", "urllib.request",
    "fastapi", "uvicorn", "asyncio", "ssl",
    "staykey.db", "staykey.api", "staykey.reservation", "staykey.app_state",
    "staykey.keys", "staykey.lifecycle", "staykey.connectedroom",
}


def _transitive_imports(module_name: str) -> set[str]:
    """Walk imports declared in the source of a module and its local deps."""
    import ast

    seen: set[str] = set()
    to_visit = [module_name]
    collected: set[str] = set()
    while to_visit:
        name = to_visit.pop()
        if name in seen:
            continue
        seen.add(name)
        mod = importlib.import_module(name)
        src_file = getattr(mod, "__file__", None)
        if not src_file or not src_file.endswith(".py"):
            continue
        tree = ast.parse(open(src_file).read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    collected.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                base = ("." * (node.level or 0)) + (node.module or "")
                resolved = _resolve_relative(name, node.level, node.module)
                collected.add(resolved if node.level else (node.module or base))
                # follow local staykey deps to walk transitively
                if resolved.startswith("staykey"):
                    to_visit.append(resolved)
    return collected


def _resolve_relative(current: str, level: int, module: str | None) -> str:
    if not level:
        return module or ""
    parts = current.split(".")
    base = parts[: len(parts) - level + 1]
    if module:
        base = parts[: len(parts) - level] + [module]
    return ".".join(base)


def test_lock_import_closure_has_no_db_or_network():
    imports = _transitive_imports("staykey.lock")
    bad = {imp for imp in imports if imp in FORBIDDEN}
    assert bad == set(), f"offline verifier must not import DB/network modules, found: {bad}"


def test_credential_import_closure_has_no_db_or_network():
    imports = _transitive_imports("staykey.credential")
    bad = {imp for imp in imports if imp in FORBIDDEN}
    assert bad == set(), f"credential core must not import DB/network modules, found: {bad}"


def test_verifier_works_with_db_and_socket_disabled(monkeypatch):
    property_sk = credential.private_from_raw  # noqa: F841  (ensure module import works)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.generate()
    pub_raw = credential.public_raw(sk.public_key())
    now = 1_800_000_000
    issued = credential.issue_credential(
        property_sk=sk, guest_id="g", stay_id="s", property_id="P", room_ids=[101],
        valid_from=now - 10, valid_until=now + 10, issued_at=now - 10,
    )

    # Booby-trap the DB + network. If the verifier touches them, the test fails.
    def _boom(*a, **k):
        raise AssertionError("offline verifier touched a forbidden resource")

    monkeypatch.setattr(sqlite3, "connect", _boom)
    monkeypatch.setattr(socket, "socket", _boom)

    lock = LockVerifier(property_id="P", room_id=101, property_pub_raw=pub_raw,
                        revoked={"some-other-id"})
    challenge = lock.begin_unlock(now)
    response = credential.device_sign(issued.device_sk_b64, challenge)
    decision = lock.finish_unlock(token=issued.token, challenge=challenge, response=response, now=now)
    assert decision.unlocked

    # Revocation is consulted from the local snapshot only (no lookup anywhere).
    lock.sync_revocations({issued.key_id})
    ch2 = lock.begin_unlock(now)
    resp2 = credential.device_sign(issued.device_sk_b64, ch2)
    d2 = lock.finish_unlock(token=issued.token, challenge=ch2, response=resp2, now=now)
    assert not d2.unlocked and d2.reason.value == "revoked"
