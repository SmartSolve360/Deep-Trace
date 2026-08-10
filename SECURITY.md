# DEEP-TRACE — Security Model

This document describes the security guarantees and trust assumptions of
DEEP-TRACE v1, what an attacker can and cannot do, and the operational
requirements for production deployments.

## Threat model

| Adversary                | Goal                                          | Defence                                                |
| ------------------------ | --------------------------------------------- | ------------------------------------------------------ |
| Forger                   | Forge a watermarked asset without a valid key | HMAC-SHA256 payload, Replay-protected challenges       |
| Replayer                 | Re-use a captured embed response              | Per-account HMAC challenge with nonce + TTL            |
| Cropper                  | Remove watermark by cropping                  | Block-padded payload, sync pattern, perceptual match  |
| Re-compressor            | Remove watermark by re-encoding               | DCT-QIM in mid-band, Reed-Solomon ECC, adaptive delta  |
| Ledger tamperer          | Modify stored ledger entries                  | `chain_of_custody_hash`, C2PA manifest, audit trail    |
| Privacy attacker         | Recover account_id from the ledger            | Pedersen commitment over (payload, hashes, account)    |
| Forgery (ZKP)            | Construct alternate commitment openings       | Generator `h` derived from server secret via HKDF      |
| API abuser               | Spam the embed endpoint                       | `X-API-Key` required, constant-time compare            |

Out of scope for v1: denial-of-service at scale (use a CDN + WAF),
side-channel attacks on the watermark extraction (timing, power),
insider threats (operational controls).

## Cryptographic primitives

| Purpose              | Algorithm                                  | Parameters                                    |
| -------------------- | ------------------------------------------ | --------------------------------------------- |
| Payload              | HMAC-SHA256                                | 128-bit truncated output                      |
| Block permutation    | HMAC-DRBG (NIST SP 800-90A)                | 256-bit security strength                     |
| Key derivation       | HKDF-style HMAC-SHA256 Expand              | 32-byte sub-keys per engine                   |
| Error correction     | Reed-Solomon RS(255, 223) over GF(2^8)     | 32 parity bytes (corrects 16-byte errors)     |
| Watermark modulation | Quantization Index Modulation              | Δ = 20, adaptive × (1 + energy/100)           |
| ZKP commitment       | Pedersen commitment over RFC 3526 MODP     | 2048-bit safe prime, g = 2                     |
| API authentication   | Constant-time string compare               | 256-bit API keys, opaque tokens               |
| Replay protection    | HMAC challenge w/ nonce + iat + exp        | TTL 300s (challenge), 600s (nonce)            |

## Trust assumptions

1. **`SECRET_KEY` is confidential.** A 32-byte high-entropy random value,
   stored only in the deployment's secret store (Vault, AWS Secrets
   Manager, sealed-secrets, etc.). Loss of this key compromises:
   - HMAC payload forgery (attacker can mint valid watermarks)
   - Pedersen binding property (attacker can find alternate openings)
   - HMAC challenges (attacker can issue valid challenges)

2. **API keys are confidential.** Same storage as `SECRET_KEY`. Loss
   allows arbitrary embed/extract/ledger reads.

3. **Postgres is trusted.** The DB stores the ledger; the trust model
   assumes row-level integrity. For tamper-evident storage in
   adversarial environments, add an append-only audit table or use
   a blockchain anchor (out of scope for v1).

4. **C2PA signing key is confidential.** Loss allows forging C2PA
   manifests that would verify as legitimate DEEP-TRACE output.

5. **The server is not compromised.** Standard server hardening
   applies. Watermark extraction is constant-time, but the rest of
   the stack has the usual web-app attack surface (XSS, SSRF, etc.).

## Pedersen commitment: critical detail

The `h` generator in the Pedersen commitment is derived from
`SECRET_KEY` via HKDF. The security of the binding property
(infeasibility of finding alternate openings) reduces to the
infeasibility of computing `log_g(h)` in the 2048-bit MODP group.

**This is NOT the same as a "nothing-up-my-sleeve" Pedersen
generator** where `h` is chosen via a verifiable ceremony. A
sufficiently motivated attacker who recovers `SECRET_KEY` can
compute `log_g(h)` and break binding. The HKDF construction only
provides computational binding under the DL assumption in the
MODP group, conditional on the confidentiality of `SECRET_KEY`.

For settings where `SECRET_KEY` rotation is impossible, replace
the HKDF-derived `h` with a true nothing-up-my-sleeve generator
(e.g., via a Powers-of-Tau ceremony or a hash-to-curve function
with a public specification). See `app/engine/zkp.py` for the
construction site.

## Evidence handling

The system aligns with **ISO/IEC 27037:2012** for digital evidence
handling. Every API response carries
`evidence_handling_standard: "ISO/IEC 27037:2012"` so downstream
chain-of-custody records can cite the standard unambiguously.

The `chain_of_custody_hash` column stores a SHA-256 over the
canonical binding tuple. Any modification of the row will fail
this check, providing tamper evidence.

## Reporting vulnerabilities

If you find a security issue, please email
**security@deep-trace.example.com** (replace with your real
contact). Do not file public issues until a fix is published.
