"""Fuzzy perceptual-hash search index

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-08

Adds:
    - pg_trgm extension
    - hamming_hex(a text, b text) -> integer SQL function
    - GIN trigram index on perceptual_hash_phash
"""
from __future__ import annotations

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Trigram operator class (no-op if already installed)
    op.execute('CREATE EXTENSION IF NOT EXISTS "pg_trgm"')

    # SQL function for exact bit-level Hamming distance on hex strings
    op.execute(
        """
        CREATE OR REPLACE FUNCTION hamming_hex(a text, b text)
        RETURNS integer
        LANGUAGE sql
        IMMUTABLE
        PARALLEL SAFE
        AS $func$
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
        $func$;
        """
    )

    # GIN + trigram indexes for fuzzy perceptual search
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_ledger_phash_trgm "
        "ON asset_provenance_ledger "
        "USING gin (perceptual_hash_phash gin_trgm_ops);"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_ledger_dhash_trgm "
        "ON asset_provenance_ledger "
        "USING gin (perceptual_hash_dhash gin_trgm_ops);"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_ledger_dhash_trgm;")
    op.execute("DROP INDEX IF EXISTS idx_ledger_phash_trgm;")
    op.execute("DROP FUNCTION IF EXISTS hamming_hex(text, text);")
    # Don't drop the pg_trgm extension — other apps may depend on it.
