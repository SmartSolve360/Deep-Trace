"""Initial schema

Revision ID: 0001
Revises:
Create Date: 2026-08-07

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')

    op.create_table(
        "asset_provenance_ledger",
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("payload_hex", sa.String(64), nullable=False),
        sa.Column("zkp_commitment_hex", sa.String(512), nullable=False),
        sa.Column("zkp_opening_value", sa.String(512), nullable=True),
        sa.Column("zkp_opening_randomness", sa.String(512), nullable=True),
        sa.Column("perceptual_hash_phash", sa.String(64), nullable=False),
        sa.Column("perceptual_hash_dhash", sa.String(64), nullable=False),
        sa.Column("perceptual_hash_ahash", sa.String(64), nullable=False),
        sa.Column("perceptual_hash_whash", sa.String(64), nullable=False),
        sa.Column("c2pa_manifest_reference", sa.Text, nullable=True),
        sa.Column("c2pa_manifest_uuid", sa.String(64), nullable=True),
        sa.Column("c2pa_embedded", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("creation_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("account_id", sa.String(128), nullable=False),
        sa.Column("account_public_key", sa.String(128), nullable=False),
        sa.Column("device_signature", sa.String(128), nullable=False),
        sa.Column("generator_model_id", sa.String(100), nullable=False, server_default="deep-trace-engine/1.0.0"),
        sa.Column("original_filename", sa.String(512), nullable=True),
        sa.Column("content_type", sa.String(64), nullable=False, server_default="image/png"),
        sa.Column("file_size_bytes", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("image_width", sa.Integer, nullable=False, server_default="0"),
        sa.Column("image_height", sa.Integer, nullable=False, server_default="0"),
        sa.Column("psnr_db", sa.Float, nullable=True),
        sa.Column("watermarked_image", sa.LargeBinary(), nullable=True),
        sa.Column("chain_of_custody_hash", sa.String(128), nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.create_index("ix_ledger_payload", "asset_provenance_ledger", ["payload_hex"])
    op.create_index("ix_ledger_commitment", "asset_provenance_ledger", ["zkp_commitment_hex"])
    op.create_index("ix_ledger_phash", "asset_provenance_ledger", ["perceptual_hash_phash"])
    op.create_index("ix_ledger_dhash", "asset_provenance_ledger", ["perceptual_hash_dhash"])
    op.create_index("ix_ledger_account", "asset_provenance_ledger", ["account_id"])
    op.create_index("ix_ledger_creation_ts", "asset_provenance_ledger", ["creation_timestamp"])
    op.create_index("ix_ledger_account_created", "asset_provenance_ledger", ["account_id", sa.text("created_at DESC")])
    op.create_index("ix_ledger_phash_account", "asset_provenance_ledger", ["perceptual_hash_phash", "account_id"])

    # updated_at trigger
    op.execute(
        """
        CREATE OR REPLACE FUNCTION set_updated_at()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = CURRENT_TIMESTAMP;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_ledger_updated_at
        BEFORE UPDATE ON asset_provenance_ledger
        FOR EACH ROW
        EXECUTE FUNCTION set_updated_at();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_ledger_updated_at ON asset_provenance_ledger")
    op.execute("DROP FUNCTION IF EXISTS set_updated_at()")
    op.drop_table("asset_provenance_ledger")
