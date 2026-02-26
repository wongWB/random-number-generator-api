# True RNG API

A true random number generator API using hardware entropy sources, with no dependency on pseudo-random algorithms for output.

## How It Works

Every request runs the following pipeline:

```
Step 1: OS urandom (32 bytes)          ← CSPRNG from kernel entropy pool
Step 2: CPU hardware RNG (32 bytes)    ← getrandom() / BCryptGenRandom / /dev/random
Step 3: Block count chosen (1–20)      ← from 1 entropy byte, randomises mixing rounds
Step 4: XOR all blocks together        ← combines entropy, output >= best source
Step 5: SHA-3-256 final pass           ← uniform distribution, 256 bits output
```

The 1–20 block count means each request does a variable number of mixing rounds,
making the process itself unpredictable.

## Project Structure

```
true-rng/
├── core/
│   └── entropy.py      # Entropy engine (XOR mixer, SHA-3, formatters)
├── api/
│   └── main.py         # FastAPI application and endpoints
├── tests/
│   └── test_entropy.py # 11 tests covering correctness and distribution
├── requirements.txt
└── README.md
```

## Running Locally

### Setup with Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the API
uvicorn api.main:app --reload --port 8000

# Run tests
python tests/test_entropy.py
```

### Quick Setup (Without Virtual Environment)

```bash
pip install -r requirements.txt

# Run the API
uvicorn api.main:app --reload --port 8000

# Run tests
python tests/test_entropy.py
```

### Uninstall Guide

```bash
# If using virtual environment, simply delete the venv folder
# On Windows:
rmdir /s venv
# On macOS/Linux:
rm -rf venv

# If installed globally, uninstall packages
pip uninstall -r requirements.txt -y
```

## API Endpoints

| Endpoint | Description | Example |
|---|---|---|
| `GET /random/integer` | Integer in [min, max] | `?min=1&max=100` |
| `GET /random/float` | Float in [min, max] | `?min=0&max=1.0` |
| `GET /random/hex` | Hex string | `?bytes_count=32` |
| `GET /random/4digit` | 4-digit number (0000–9999) | — |
| `GET /random/dice` | Dice roll | `?sides=20` |
| `GET /random/uuid` | UUID v4 from true entropy | — |
| `GET /random/shuffle` | Shuffle a list | `?items=a,b,c,d` |
| `GET /random/lottery` | Lottery numbers (unique, sorted) | `?min=1&max=49&count=6` |
| `GET /health` | Source diagnostics | — |

Interactive docs available at `/docs` when running locally.

### Lottery Endpoint Details

The `/random/lottery` endpoint is designed for lottery and number picker applications:

**Parameters:**
- `min` (default: 1) - Minimum number in the range (inclusive)
- `max` (default: 49) - Maximum number in the range (inclusive)
- `count` (default: 6) - How many unique numbers to pick

**Common Use Cases:**
- Singapore TOTO: `?min=1&max=49&count=6`
- Powerball (main): `?min=1&max=69&count=5`
- Mega Millions (main): `?min=1&max=70&count=5`
- EuroMillions (main): `?min=1&max=50&count=5`

**Validation:**
- Maximum 100 numbers can be picked
- Range size limited to 1000 numbers
- Count cannot exceed available range size

## Example Response

```json
{
  "value": "4827",
  "entropy_bits": 256,
  "mixing_rounds": 13,
  "sources": ["os_urandom", "cpu_hardware_rng"],
  "timestamp": 1709123456.789
}
```

## Entropy Sources

| Source | Type | Platform | Fallback |
|---|---|---|---|
| `os.urandom` | CSPRNG (kernel pool) | All | Always available |
| `getrandom()` syscall | Kernel entropy pool | Linux | Falls back to second urandom call |
| `BCryptGenRandom` | Hardware-backed | Windows | Falls back to second urandom call |
| `/dev/random` | Hardware-backed | macOS | Falls back to second urandom call |

## Deploying to RapidAPI

1. Deploy to any cloud host (Railway, Render, AWS, etc.)
2. Go to RapidAPI → Provider Dashboard → Add New API
3. Point to your deployed URL
4. Configure endpoints, pricing tiers, and rate limits
5. Submit for marketplace listing

## License Considerations

This API uses only OS and CPU-level entropy — no third-party entropy APIs.
This means no upstream license restrictions on monetisation.

If you later add Random.org or ANU QRNG as supplementary sources,
purchase their Commercial license tier before monetising.
