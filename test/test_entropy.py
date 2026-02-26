"""
tests/test_entropy.py — Validate entropy engine correctness

Tests cover:
  - Output is always the right size
  - XOR mixing is happening (outputs are non-zero)
  - SHA-3 output is deterministically sized
  - Integer range conversion is within bounds
  - Float is in [0.0, 1.0)
  - No two outputs are identical (probabilistic, extremely unlikely to fail)
  - Block count is always 1–20
  - Rejection sampling stays in range under repeated calls
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import hashlib
from core.entropy import (
    build_entropy_pool,
    entropy_to_int,
    entropy_to_float,
    entropy_to_hex,
)


def test_pool_output_size():
    pool = build_entropy_pool()
    assert len(pool["entropy_bytes"]) == 32, "SHA-3-256 should produce 32 bytes"
    assert pool["output_bits"] == 256


def test_block_count_range():
    """Block count must always be 1–20."""
    for _ in range(50):
        pool = build_entropy_pool()
        assert 1 <= pool["block_count"] <= 20, f"Block count out of range: {pool['block_count']}"


def test_output_not_zero():
    """Output should never be all-zero bytes."""
    pool = build_entropy_pool()
    assert pool["entropy_bytes"] != bytes(32), "Output is all zeros — entropy failure"


def test_uniqueness():
    """Two consecutive outputs should never be identical."""
    outputs = set()
    for _ in range(20):
        pool = build_entropy_pool()
        h = pool["entropy_bytes"].hex()
        assert h not in outputs, f"Duplicate entropy output detected: {h}"
        outputs.add(h)


def test_integer_range():
    """entropy_to_int must stay within [min, max] inclusive."""
    for _ in range(100):
        pool = build_entropy_pool()
        value = entropy_to_int(pool["entropy_bytes"], 0, 9999)
        assert 0 <= value <= 9999, f"4-digit value out of range: {value}"


def test_integer_range_small():
    """Works correctly for small ranges like dice."""
    for _ in range(200):
        pool = build_entropy_pool()
        value = entropy_to_int(pool["entropy_bytes"], 1, 6)
        assert 1 <= value <= 6, f"Dice value out of range: {value}"


def test_float_range():
    """Float must be in [0.0, 1.0)."""
    for _ in range(50):
        pool = build_entropy_pool()
        value = entropy_to_float(pool["entropy_bytes"])
        assert 0.0 <= value < 1.0, f"Float out of range: {value}"


def test_hex_output():
    """Hex output must be valid hex and correct length."""
    pool = build_entropy_pool()
    h = entropy_to_hex(pool["entropy_bytes"])
    assert len(h) == 64, "SHA-3-256 hex should be 64 chars"
    int(h, 16)  # Raises ValueError if not valid hex


def test_4digit_distribution():
    """Basic distribution check — all outputs should not cluster."""
    results = set()
    for _ in range(30):
        pool = build_entropy_pool()
        value = entropy_to_int(pool["entropy_bytes"], 0, 9999)
        results.add(value)
    # With 30 draws from 10000, expect high uniqueness
    assert len(results) >= 25, f"Too many collisions in 4-digit output: {len(results)} unique"


def test_sources_reported():
    """Sources used should always include os_urandom."""
    pool = build_entropy_pool()
    assert any("os_urandom" in s for s in pool["sources_used"]), \
        "os_urandom should always be in sources"


def test_sha3_consistency():
    """Same input to SHA-3 should always produce same output (sanity check)."""
    test_input = b"test_entropy_input_fixed"
    h1 = hashlib.sha3_256(test_input).digest()
    h2 = hashlib.sha3_256(test_input).digest()
    assert h1 == h2, "SHA-3 is not deterministic — critical error"


if __name__ == "__main__":
    tests = [
        test_pool_output_size,
        test_block_count_range,
        test_output_not_zero,
        test_uniqueness,
        test_integer_range,
        test_integer_range_small,
        test_float_range,
        test_hex_output,
        test_4digit_distribution,
        test_sources_reported,
        test_sha3_consistency,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f"  ✓ {test.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  ✗ {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"  ✗ {test.__name__} (exception): {e}")
            failed += 1

    print(f"\n{passed}/{passed + failed} tests passed")
