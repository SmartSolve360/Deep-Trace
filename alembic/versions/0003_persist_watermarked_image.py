"""Persist watermarked image bytes

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-08

Adds the `watermarked_image` bytea column to asset_provenance_ledger so
the public GET /asset/{id}/image endpoint can re-serve the watermarked
PNG without re-running the embed pipeline.

Existing rows keep `watermarked_image = NULL` and will return 410 Gone
from the public endpoint until they are re-embedded.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Use raw SQL with IF NOT EXISTS so this migration is idempotent
    # (safe to re-run if a previous deploy partially applied it).
    op.execute(
        "ALTER TABLE asset_provenance_ledger "
        "ADD COLUMN IF NOT EXISTS watermarked_image BYTEA"
    )


def downgrade() -> None:
    op.drop_column("asset_provenance_ledger", "watermarked_image")
