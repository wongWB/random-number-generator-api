"""
main.py — FastAPI True RNG API

Endpoints:
  GET /random/integer     → integer in [min, max]
  GET /random/float       → float in [min, max]
  GET /random/hex         → hex string
  GET /random/bytes       → raw bytes as hex
  GET /random/4digit      → 4-digit number (0000–9999) for lottery use
  GET /random/dice        → dice roll (d4, d6, d8, d10, d12, d20, d100)
  GET /random/uuid        → UUID v4 from true entropy
  GET /random/shuffle     → shuffle a list of items
  GET /random/lottery     → lottery numbers (e.g., Singapore TOTO 1-49, pick 6)
  GET /health             → entropy source health and pool diagnostics
"""

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uuid
import time
import logging

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.entropy import (
    build_entropy_pool,
    entropy_to_int,
    entropy_to_float,
    entropy_to_hex,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="True RNG API",
    description=(
        "A true random number generator using hardware entropy sources. "
        "Each request mixes OS urandom and CPU hardware RNG across 1–20 "
        "randomised rounds before a SHA-3 final pass."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
# Response models
# ─────────────────────────────────────────────

class RandomResponse(BaseModel):
    value: object
    entropy_bits: int
    mixing_rounds: int
    sources: list[str]
    timestamp: float


class HealthResponse(BaseModel):
    status: str
    sources: dict
    last_pool_diagnostics: Optional[dict]


# ─────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────

def generate(block_size: int = 32) -> dict:
    """Generate a fresh entropy pool and return it with metadata."""
    pool = build_entropy_pool(block_size=block_size)
    return pool


def make_response(value: object, pool: dict) -> RandomResponse:
    return RandomResponse(
        value=value,
        entropy_bits=pool["output_bits"],
        mixing_rounds=pool["rounds_completed"],
        sources=pool["sources_used"],
        timestamp=time.time(),
    )


# ─────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────

@app.get("/random/integer", response_model=RandomResponse)
def random_integer(
    min: int = Query(default=0, description="Minimum value (inclusive)"),
    max: int = Query(default=100, description="Maximum value (inclusive)"),
):
    """Generate a true random integer between min and max (inclusive)."""
    if min >= max:
        raise HTTPException(status_code=400, detail="min must be less than max")
    if (max - min) > 10_000_000:
        raise HTTPException(status_code=400, detail="Range too large (max 10,000,000)")

    pool = generate()
    value = entropy_to_int(pool["entropy_bytes"], min, max)
    return make_response(value, pool)

#update float to  input min and max range
@app.get("/random/float", response_model=RandomResponse)
def random_float(
    min: float = Query(default=0.0, description="Minimum value (inclusive)"),
    max: float = Query(default=1.0, description="Maximum value (inclusive)")
):
    """Generate a true random float between min and max (inclusive)."""
    if min >= max:
        raise HTTPException(status_code=400, detail="min must be less than max")
    if (max - min) > 10_000_000:
        raise HTTPException(status_code=400, detail="Range too large (max 10,000,000)")

    pool = generate()
    value = entropy_to_float(pool["entropy_bytes"], min, max)
    return make_response(round(value, 15), pool)


@app.get("/random/hex", response_model=RandomResponse)
def random_hex(
    bytes_count: int = Query(default=32, ge=1, le=64, description="Number of bytes (1–64)")
):
    """Generate true random bytes returned as a hex string."""
    pool = generate(block_size=max(32, bytes_count))
    value = entropy_to_hex(pool["entropy_bytes"])[:bytes_count * 2]
    return make_response(value, pool)


@app.get("/random/4digit", response_model=RandomResponse)
def random_4digit():
    """
    Generate a 4-digit number (0000–9999) padded with leading zeros.
    Suitable for use cases requiring a 4-digit output (e.g. number pickers).
    """
    pool = generate()
    value = entropy_to_int(pool["entropy_bytes"], 0, 9999)
    # Pad to 4 digits with leading zeros
    formatted = str(value).zfill(4)
    return make_response(formatted, pool)


@app.get("/random/dice", response_model=RandomResponse)
def random_dice(
    sides: int = Query(default=6, description="Dice sides: 4, 6, 8, 10, 12, 20, or 100")
):
    """Roll a true random dice."""
    valid_sides = {4, 6, 8, 10, 12, 20, 100}
    if sides not in valid_sides:
        raise HTTPException(
            status_code=400,
            detail=f"Sides must be one of: {sorted(valid_sides)}"
        )
    pool = generate()
    value = entropy_to_int(pool["entropy_bytes"], 1, sides)
    return make_response(value, pool)


@app.get("/random/uuid", response_model=RandomResponse)
def random_uuid():
    """Generate a UUID v4 seeded from true hardware entropy."""
    pool = generate()
    entropy = pool["entropy_bytes"]
    # Build UUID v4 from entropy bytes
    # UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    # where y is 8, 9, a, or b
    b = bytearray(entropy[:16])
    b[6] = (b[6] & 0x0F) | 0x40   # version 4
    b[8] = (b[8] & 0x3F) | 0x80   # variant bits
    value = str(uuid.UUID(bytes=bytes(b)))
    return make_response(value, pool)


@app.get("/random/shuffle", response_model=RandomResponse)
def random_shuffle(
    items: str = Query(..., description="Comma-separated list of items to shuffle")
):
    """Shuffle a list of items using true entropy (Fisher-Yates)."""
    item_list = [i.strip() for i in items.split(",") if i.strip()]
    if len(item_list) < 2:
        raise HTTPException(status_code=400, detail="Provide at least 2 items")
    if len(item_list) > 100:
        raise HTTPException(status_code=400, detail="Max 100 items")

    # Fisher-Yates shuffle using fresh entropy per swap
    pool = generate()
    for i in range(len(item_list) - 1, 0, -1):
        # Fresh entropy byte(s) for each swap position
        j = entropy_to_int(pool["entropy_bytes"], 0, i)
        item_list[i], item_list[j] = item_list[j], item_list[i]
        # Refresh entropy via SHA-3 chaining
        import hashlib
        pool["entropy_bytes"] = hashlib.sha3_256(pool["entropy_bytes"]).digest()

    return make_response(item_list, pool)


@app.get("/random/lottery", response_model=RandomResponse)
def random_lottery(
    min: int = Query(default=1, ge=1, description="Minimum number (inclusive)"),
    max: int = Query(default=49, description="Maximum number (inclusive)"),
    count: int = Query(default=6, ge=1, description="How many unique numbers to pick")
):
    """
    Generate unique lottery numbers (e.g., Singapore TOTO: 1-49, pick 6).
    Uses Fisher-Yates shuffle algorithm with true entropy.
    """
    if min >= max:
        raise HTTPException(status_code=400, detail="min must be less than max")

    range_size = max - min + 1
    if count > range_size:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot pick {count} unique numbers from range {min}-{max} (only {range_size} numbers available)"
        )

    if count > 100:
        raise HTTPException(status_code=400, detail="Max 100 numbers can be picked")

    if range_size > 1000:
        raise HTTPException(status_code=400, detail="Range too large (max 1000)")

    # Create array of all numbers in range
    numbers = list(range(min, max + 1))

    # Fisher-Yates shuffle using true entropy, but only shuffle enough for our needs
    pool = generate()
    for i in range(count):
        # Pick random index from remaining unshuffled portion
        j = entropy_to_int(pool["entropy_bytes"], i, len(numbers) - 1)
        # Swap current position with randomly selected position
        numbers[i], numbers[j] = numbers[j], numbers[i]
        # Refresh entropy via SHA-3 chaining for next iteration
        import hashlib
        pool["entropy_bytes"] = hashlib.sha3_256(pool["entropy_bytes"]).digest()

    # Take first 'count' numbers and sort them (lottery numbers are typically displayed sorted)
    result = sorted(numbers[:count])

    return make_response(result, pool)


# ─────────────────────────────────────────────
# Health check
# ─────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
def health_check():
    """
    Run a diagnostics pool generation and report source availability.
    """
    from core.entropy import get_cpu_entropy
    import os

    # Test each source
    os_status = "active"
    try:
        os.urandom(32)
    except Exception:
        os_status = "error"

    cpu_status = "active"
    try:
        result = get_cpu_entropy(32)
        if result is None:
            cpu_status = "unavailable_using_fallback"
    except Exception:
        cpu_status = "error"

    # Run a real pool generation for diagnostics
    pool = build_entropy_pool()

    return HealthResponse(
        status="ok" if os_status == "active" else "degraded",
        sources={
            "os_urandom": os_status,
            "cpu_hardware_rng": cpu_status,
        },
        last_pool_diagnostics={
            "mixing_rounds": pool["rounds_completed"],
            "block_count_chosen": pool["block_count"],
            "sources_contributing": pool["sources_used"],
            "entropy_bits": pool["output_bits"],
        }
    )


@app.get("/")
def root():
    return {
        "name": "True RNG API",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": [
            "/random/integer",
            "/random/float",
            "/random/hex",
            "/random/4digit",
            "/random/dice",
            "/random/uuid",
            "/random/shuffle",
            "/random/lottery",
            "/health",
        ]
    }
