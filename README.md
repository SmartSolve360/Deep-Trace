# DEEP-TRACE Engine

> **Forensic content-provenance service.**
> Bind cryptographic identity to media. Detect origin. Survive recompression.

DEEP-TRACE is a FastAPI service that embeds an invisible, robust
watermark in the frequency domain of an image, binds it to an account +
device + timestamp, and registers the binding in a tamper-evident
ledger. The watermark can later be extracted from a suspect image to
verify provenance — even after JPEG recompression, mild filtering, or
resize.

The system is designed for **forensic and legal contexts** where the
chain of custody and cryptographic non-repudiation matter as much as the
detection itself. Evidence handling follows **ISO/IEC 27037:2012**.

---

## What it does

```
┌─────────────┐      ┌─────────────────┐      ┌──────────────────────┐
│ Source image│─────▶│  DEEP-TRACE     │─────▶│ Watermarked image    │
│  (any size  │      │  /watermark/    │      │ + ledger receipt     │
│  ≥128x128)  │      │   embed         │      │ + C2PA manifest      │
└─────────────┘      └─────────────────┘      └──────────────────────┘
                                                       │
┌─────────────┐      ┌─────────────────┐               ▼
│ Suspect     │─────▶│  DEEP-TRACE     │      ┌──────────────────────┐
│ image       │      │  /forensics/    │      │ Provenance ledger    │
│             │      │   extract       │      │ (PostgreSQL)         │
└─────────────┘      └─────────────────┘      └──────────────────────┘
```

Two operations:

| Operation | Endpoint                       | Auth          |
| --------- | ------------------------------ | ------------- |
| Embed     | `POST /api/v1/watermark/embed` | `X-API-Key`   |
| Extract   | `POST /api/v1/forensics/extract` | `X-API-Key` |
| Verify    | `POST /api/v1/forensics/verify/{asset_id}` | `X-API-Key` + `X-Challenge` |
| Look up   | `GET  /api/v1/ledger/{asset_id}` | `X-API-Key` |
| Search    | `GET  /api/v1/ledger/search?phash=...` | `X-API-Key` |
| Challenge | `POST /api/v1/auth/challenge`  | `X-API-Key`   |
| Health    | `GET  /health` / `GET /ready`  | (open)        |

---

## Architecture

```
deep_trace/
├── app/
│   ├── main.py              # FastAPI app, lifespan, exception handlers
│   ├── config.py            # Pydantic Settings
│   ├── database.py          # Async SQLAlchemy engine + session
│   ├── core/                # cross-cutting concerns
│   │   ├── security.py      # HKDF, HMAC, challenges, API keys
│   │   ├── logging.py       # structlog
│   │   └── exceptions.py    # exception hierarchy
│   ├── engine/              # the math
│   │   ├── watermark.py     # DCT-QIM embedder/extractor
│   │   ├── perceptual.py    # pHash / dHash / aHash / wHash
│   │   ├── zkp.py           # Pedersen commitment
│   │   ├── c2pa_wrapper.py  # C2PA manifest gen/validate
│   │   ├── ecc.py           # Reed-Solomon error correction
│   │   └── prng.py          # HMAC-DRBG keyed PRNG
│   ├── models/              # SQLAlchemy ORM
│   │   ├── base.py
│   │   └── asset.py         # asset_provenance_ledger table
│   ├── schemas/             # Pydantic request/response
│   ├── services/            # business logic
│   │   ├── ledger.py        # provenance ledger CRUD
│   │   ├── auth.py          # API key + challenge
│   │   └── forensics.py     # end-to-end workflows
│   ├── api/
│   │   ├── deps.py          # FastAPI dependencies
│   │   └── v1/              # routers
│   │       ├── watermark.py
│   │       ├── forensics.py
│   │       ├── ledger.py
│   │       ├── auth.py
│   │       └── health.py
│   └── utils/
│       ├── image.py         # OpenCV I/O + validation
│       └── encoding.py      # hex, base64url, timestamps
├── tests/
│   ├── unit/                # pure engine tests
│   └── conftest.py
├── scripts/
│   └── verify_installation.py
├── schema.sql               # Postgres bootstrap schema
├── Dockerfile               # multi-stage
├── docker-compose.yml       # API + Postgres
├── requirements.txt
├── pytest.ini
├── .env.example
├── .dockerignore
└── .gitignore
```

---

## Watermark scheme

| Property            | Value                                                 |
| ------------------- | ----------------------------------------------------- |
| Domain              | YCbCr luminance, 8×8 DCT blocks                       |
| Mid-band coefs      | (2,1), (1,2), (2,2), (3,1)                            |
| Bits per block      | 4                                                     |
| Modulation          | QIM (even/odd parity), delta = 20                     |
| Adaptive delta      | × (1 + block_energy/100)                              |
| Sync pattern        | Fixed '1' in (4,1) of first 4 blocks                  |
| Payload             | 128-bit HMAC-SHA256(secret, account_id ‖ ts ‖ dev)    |
| Error correction    | Reed-Solomon RS(48, 16) — corrects up to 16 byte errs |
| Min image size      | 128×128                                               |
| Typical PSNR        | ≥ 38 dB (natural images)                              |
| Survives            | JPEG @ Q=85, mild Gaussian noise (σ ≤ 5)              |

---

## Quick start

### Option 1 — Docker Compose (recommended)

```bash
# 1. Clone / enter the project
cd deep_trace

# 2. Generate strong secrets and put them in .env
cp .env.example .env
python -c "import secrets; print('DEEPTRACE_SECRET_KEY=' + secrets.token_urlsafe(32))" >> .env
python -c "import secrets; print('DEEPTRACE_API_KEYS=' + secrets.token_urlsafe(32))" >> .env

# 3. Bring up the stack (Postgres + API)
docker compose up --build

# 4. Verify
curl http://localhost:8000/health
curl http://localhost:8000/ready
open http://localhost:8000/docs   # Swagger UI
```

### Option 2 — local Python

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env               # then edit SECRET_KEY and API_KEYS
# Bring up Postgres any way you like; default DSN points at host `db`
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Option 3 — verify installation without bringing up the DB

```bash
python scripts/verify_installation.py
```

This runs a self-test of every engine (watermark, ZKP, ECC, hashing, HMAC)
without needing Postgres.

---

## Example: embed a watermark

```bash
# Issue a challenge (optional for /embed, required for /verify)
curl -X POST http://localhost:8000/api/v1/auth/challenge \
    -H "X-API-Key: $DEEPTRACE_API_KEYS" \
    -H "Content-Type: application/json" \
    -d '{"account_id":"acct-42"}'

# Embed a watermark
curl -X POST http://localhost:8000/api/v1/watermark/embed \
    -H "X-API-Key: $DEEPTRACE_API_KEYS" \
    -F "file=@photo.png" \
    -F "account_id=acct-42" \
    -F "account_public_key=04abcd1234..." \
    -F "device_signature=dev-abc-123" \
    -o response.json

cat response.json | jq .
# {
#   "status": "SUCCESS",
#   "asset_id": "f3a1...-...",
#   "payload_hex": "a1b2c3d4...",
#   "zkp_commitment_hex": "9f8e...",
#   "perceptual_hashes": { "phash": "...", "dhash": "...", ... },
#   "c2pa": { "manifest_uuid": "...", "reference": "...", "embedded": false },
#   "psnr_db": 42.31,
#   "evidence_handling_standard": "ISO/IEC 27037:2012"
# }
```

## Example: extract & match

```bash
curl -X POST http://localhost:8000/api/v1/forensics/extract \
    -H "X-API-Key: $DEEPTRACE_API_KEYS" \
    -F "file=@suspect.jpg" \
    -o extract.json

cat extract.json | jq .
# {
#   "status": "MATCH_FOUND",
#   "asset_id": "f3a1...",
#   "payload_hex": "a1b2c3d4...",
#   "ledger_match": {
#     "asset_id": "f3a1...",
#     "account_id": "acct-42",
#     "creation_timestamp": "2026-08-07T03:14:15Z",
#     "payload_match": true,
#     "perceptual_distance": { "phash": 0, "dhash": 1, ... }
#   },
#   "extraction_status": "OK (corrected 0 byte errors)"
# }
```

---

## Security model

| Concern              | Mitigation                                                |
| -------------------- | --------------------------------------------------------- |
| Replay (challenge)   | HMAC-bound nonce + iat + exp, single-use within window    |
| API abuse            | `X-API-Key` required, constant-time compare               |
| Payload forgery      | Payload is HMAC-SHA256 of account_id ‖ ts ‖ device_sig     |
| Tamper (ledger)      | `chain_of_custody_hash` SHA-256 over canonical binding    |
| Privacy              | Perceptual hashes + Pedersen commitment; no plaintext PII  |
| Master secret        | HKDF-style sub-keys for each engine — no key reuse        |
| Non-repudiation      | C2PA manifest + signed Pedersen opening                   |
| Forgery (ZKP)        | Pedersen commitment over RFC 3526 2048-bit MODP group     |
| Replay (extract)     | `/forensics/verify` requires a fresh `X-Challenge` token  |

**Production checklist:**

1. Override `DEEPTRACE_SECRET_KEY` and `DEEPTRACE_API_KEYS` from `.env`.
2. Provision C2PA signing key/cert and set `C2PA_SIGNING_*_PATH`.
3. Set `ENVIRONMENT=production` and `LOG_JSON=true`.
4. Restrict `CORS_ALLOW_ORIGINS` to your known frontends.
5. Run Postgres over TLS (`?ssl=require` in the DSN).
6. Front the API with a reverse proxy (Caddy / Traefik / nginx) for
   rate limiting, request size limits, and mTLS.
7. Back up the `manifests/` directory alongside the database.

---

## Forensic compliance

DEEP-TRACE evidence handling is aligned with **ISO/IEC 27037:2012**
(Identification, Collection, Acquisition and Preservation of Digital
Evidence):

- **Identification** — every asset gets a UUID, perceptual hashes,
  and cryptographic binding at the moment of capture.
- **Preservation** — original payload, hashes, commitment, and chain-
  of-custody hash are recorded in the immutable `asset_provenance_ledger`
  table; the C2PA manifest is preserved as a separate file.
- **Documentation** — every API response carries
  `evidence_handling_standard: "ISO/IEC 27037:2012"` for downstream
  chain-of-custody records.
- **Non-repudiation** — the Pedersen commitment binds the payload to
  the account; the C2PA manifest is signed (when signing keys are
  provisioned).

---

## Development

The repo ships with a `Makefile` for the common workflows. On Windows you can also run the same commands directly.

```bash
# Show every available target
make help

# Run the full test suite
make test

# Run just unit tests (no DB needed)
make unit

# Run integration tests (uses in-memory SQLite)
make integration

# Self-test the installation — exercises every engine
make verify

# Format and lint
make format
make lint

# Spin up Postgres + API
make compose-up

# Tail the API logs
make logs

# Tear it all down
make compose-down
```

If you don't have `make` (Windows), the underlying commands are:
```bash
# Install
pip install -r requirements.txt
pip install aiosqlite httpx pytest pytest-asyncio ruff black

# Tests
python -m pytest tests/ -v
python -m pytest tests/unit/ -v            # unit only (no DB)
python -m pytest tests/integration/ -v     # integration (uses SQLite)

# Self-test
python scripts/verify_installation.py

# Lint
ruff check app tests
black --check app tests
```

## Schema migrations (production)

For production we use Alembic instead of the `init_db()` create-all path. After changing a model:

```bash
# Generate a new migration from the current model definitions
alembic revision --autogenerate -m "add new column"

# Apply pending migrations
alembic upgrade head

# Roll back one step
alembic downgrade -1
```

The initial migration is at `alembic/versions/0001_initial.py` and mirrors `schema.sql`.

## CI

A GitHub Actions workflow at `.github/workflows/ci.yml` runs the test matrix
on Python 3.11 + 3.12 against a real Postgres service container, plus a
dependency audit via `pip-audit`.

## Example client

`examples/client_demo.py` shows the full provenance loop (challenge → embed
→ recompress → extract → verify → lookup) against a running API:

```bash
pip install httpx
python examples/client_demo.py http://localhost:8000 "$DEEPTRACE_API_KEY" photo.jpg demo-account
```

There's also a curl-only equivalent in `examples/curl_examples.sh`.

---

## Limitations of v1

- **Pedersen commitment only.** Real zk-SNARK proofs of provenance
  (e.g. "I watermarked this at time T without revealing T") are out of
  scope for v1 but the commitment is ZK-friendly and upgradeable.
- **C2PA is optional.** When `c2pa-python` and signing keys are present
  the system produces a real signed manifest; otherwise it records a
  reference UUID. A `WARN` is logged on every fallback.
- **Perceptual search is O(N).** A coarse `LIKE` over the first 8 hex
  chars of `phash`, then ranked client-side. v2 will add a specialised
  index (e.g. `pg_trgm` + bit-string hamming operator, or a dedicated
  perceptual index like `pgsparql`).
- **No image transformation attack resistance.** Heavy rotation, severe
  cropping, or aggressive filtering will destroy the watermark. Real
  forensic systems pair frequency-domain watermarks with a learned
  DNN-based embedder for these cases; that's a v2 upgrade.

---

## License

Apache-2.0. See `LICENSE`.
