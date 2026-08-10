-- =========================================================================
-- DEEP-TRACE — provenance ledger schema
-- =========================================================================
-- This file is mounted into the Postgres container at
-- /docker-entrypoint-initdb.d/01_schema.sql and runs once on first boot.
-- For production we recommend running schema changes via Alembic, not by
-- re-running this file.
--
-- The application also creates tables on startup via SQLAlchemy
-- `Base.metadata.create_all`, so this file is belt-and-braces.
-- =========================================================================

-- Required extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "pg_trgm";    -- trigram ops for fuzzy perceptual search

-- -------------------------------------------------------------------------
-- hamming_hex(a text, b text) -> integer
--
-- Computes the bit-level Hamming distance between two hex-encoded hashes
-- of equal length. Used by the fuzzy perceptual search to rank candidates
-- produced by the GIN index.
--
-- Implementation: XOR the two hex strings as raw bytes, then count the
-- set bits (popcount). For pHash (16 hex chars = 8 bytes = 64 bits) the
-- result is in [0, 64].
-- -------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION hamming_hex(a text, b text)
RETURNS integer
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT COALESCE((
        SELECT sum(((get_byte(xor_bytes, i) >> k) & 1)::int)
        FROM generate_series(0, length(a)/2 - 1) AS i,
             generate_series(0, 7) AS k
    ), 0)
    FROM (
        SELECT decode(a, 'hex') # decode(b, 'hex') AS xor_bytes
    ) AS t
    WHERE length(a) = length(b)
      AND length(a) % 2 = 0
      AND a ~ '^[0-9a-fA-F]+$'
      AND b ~ '^[0-9a-fA-F]+$';
$$;

-- -------------------------------------------------------------------------
-- Core provenance tracking table
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS asset_provenance_ledger (
    asset_id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Cryptographic binding
    payload_hex                VARCHAR(64)  NOT NULL,
    zkp_commitment_hex         VARCHAR(512) NOT NULL,
    zkp_opening_value          VARCHAR(512) NULL,
    zkp_opening_randomness     VARCHAR(512) NULL,

    -- Perceptual hashes
    perceptual_hash_phash      VARCHAR(64)  NOT NULL,
    perceptual_hash_dhash      VARCHAR(64)  NOT NULL,
    perceptual_hash_ahash      VARCHAR(64)  NOT NULL,
    perceptual_hash_whash      VARCHAR(64)  NOT NULL,

    -- C2PA
    c2pa_manifest_reference    TEXT         NULL,
    c2pa_manifest_uuid         VARCHAR(64)  NULL,
    c2pa_embedded              BOOLEAN      NOT NULL DEFAULT FALSE,

    -- Source metadata
    creation_timestamp         TIMESTAMP WITH TIME ZONE NOT NULL,
    account_id                 VARCHAR(128) NOT NULL,
    account_public_key         VARCHAR(128) NOT NULL,
    device_signature           VARCHAR(128) NOT NULL,
    generator_model_id         VARCHAR(100) NOT NULL DEFAULT 'deep-trace-engine/1.0.0',

    -- File metadata
    original_filename          VARCHAR(512) NULL,
    content_type               VARCHAR(64)  NOT NULL DEFAULT 'image/png',
    file_size_bytes            BIGINT       NOT NULL DEFAULT 0,
    image_width                INTEGER      NOT NULL DEFAULT 0,
    image_height               INTEGER      NOT NULL DEFAULT 0,
    psnr_db                    DOUBLE PRECISION NULL,
    watermarked_image          BYTEA        NULL,

    -- ISO/IEC 27037 chain-of-custody anchor
    chain_of_custody_hash      VARCHAR(128) NULL,

    -- Audit
    notes                      TEXT         NULL,
    created_at                 TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                 TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- -------------------------------------------------------------------------
-- Indexes for fast lookup
-- -------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_ledger_payload        ON asset_provenance_ledger (payload_hex);
CREATE INDEX IF NOT EXISTS idx_ledger_commitment     ON asset_provenance_ledger (zkp_commitment_hex);
CREATE INDEX IF NOT EXISTS idx_ledger_phash          ON asset_provenance_ledger (perceptual_hash_phash);
CREATE INDEX IF NOT EXISTS idx_ledger_dhash          ON asset_provenance_ledger (perceptual_hash_dhash);
CREATE INDEX IF NOT EXISTS idx_ledger_account        ON asset_provenance_ledger (account_id);
CREATE INDEX IF NOT EXISTS idx_ledger_creation_ts    ON asset_provenance_ledger (creation_timestamp);
CREATE INDEX IF NOT EXISTS idx_ledger_account_created ON asset_provenance_ledger (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ledger_phash_account  ON asset_provenance_ledger (perceptual_hash_phash, account_id);

-- -------------------------------------------------------------------------
-- GIN + trigram indexes for fuzzy perceptual search
--
-- Lets us narrow millions of rows to a candidate set whose hex
-- representation shares enough trigrams with the query. The actual
-- Hamming-distance ranking is done in SQL via hamming_hex().
--
-- We index both pHash and dHash since they capture complementary
-- perceptual features (frequency vs. gradient). Search by either is
-- sub-linear in the row count.
--
-- This index is Postgres-only; SQLite (used in tests) silently ignores
-- it because the operator class is unavailable.
-- -------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_ledger_phash_trgm
    ON asset_provenance_ledger
    USING gin (perceptual_hash_phash gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_ledger_dhash_trgm
    ON asset_provenance_ledger
    USING gin (perceptual_hash_dhash gin_trgm_ops);

-- -------------------------------------------------------------------------
-- updated_at trigger
-- -------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_ledger_updated_at ON asset_provenance_ledger;
CREATE TRIGGER trg_ledger_updated_at
    BEFORE UPDATE ON asset_provenance_ledger
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();
