"""Unit tests for Python integrity verification (issue #4)."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MOD_PATH = ROOT / "javelin_integrity.py"


def load_mod():
    spec = importlib.util.spec_from_file_location("javelin_integrity", MOD_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["javelin_integrity"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_skip_when_env_unset(monkeypatch):
    mod = load_mod()
    monkeypatch.delenv("JAVELIN_EXPECTED_SHA256", raising=False)
    assert mod.verify_integrity(MOD_PATH) == 0


def test_ok_when_hash_matches(monkeypatch):
    mod = load_mod()
    digest = hashlib.sha256(MOD_PATH.read_bytes()).hexdigest()
    monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", digest)
    assert mod.verify_integrity(MOD_PATH) == 0


def test_fail_when_hash_mismatch(monkeypatch):
    mod = load_mod()
    monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", "0" * 64)
    assert mod.verify_integrity(MOD_PATH) == mod.EXIT_INTEGRITY
