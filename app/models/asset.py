"""
Asset provenance ledger — the system-of-record for every registered asset.

Each row binds:
    - the 128-bit HMAC payload (the watermark's identity)
    - the four perceptual hashes (for content matching)
    - the Pedersen commitment (zk-friendly binding of metadata)
    - a C2PA manifest reference (Content Authenticity Initiative standard)
    - the source account + creation timestamp + device signature

Indexes:
    - B-tree on phash, dhash, commitment, account_id, payload
    - GIN + pg_trgm on phash for fuzzy perceptual lookup (Postgres only)
    - Composite B-tree on (account_id, created_at) and (phash, account_id)

Perceptual search strategy (Postgres):
    1. GIN index narrows to a candidate set of pHashes within edit distance
       of the query (fast, scales to millions of rows)
    2. The custom `hamming_hex()` SQL function computes the exact bit
       Hamming distance for ranking
    3. Top-K by distance is returned

For SQLite (dev/test), the GIN index is silently skipped and search falls
back to a coarse LIKE bucket + client-side ranking.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, Index, LargeBinary, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin


class AssetProvenanceLedger(Base, TimestampMixin):
    """Core provenance record for a single watermarked asset."""

    __tablename__ = "asset_provenance_ledger"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )

    # ---- Cryptographic binding ----
    payload_hex: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    zkp_commitment_hex: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    zkp_opening_value: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    zkp_opening_randomness: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    # ---- Perceptual hashes ----
    perceptual_hash_phash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    perceptual_hash_dhash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    perceptual_hash_ahash: Mapped[str] = mapped_column(String(64), nullable=False)
    perceptual_hash_whash: Mapped[str] = mapped_column(String(64), nullable=False)

    # ---- C2PA ----
    c2pa_manifest_reference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    c2pa_manifest_uuid: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    c2pa_embedded: Mapped[bool] = mapped_column(default=False, nullable=False)

    # ---- Source metadata ----
    creation_timestamp: Mapped[datetime] = mapped_column(nullable=False, index=True)
    account_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    account_public_key: Mapped[str] = mapped_column(String(128), nullable=False)
    device_signature: Mapped[str] = mapped_column(String(128), nullable=False)
    generator_model_id: Mapped[str] = mapped_column(String(100), nullable=False, default="deep-trace-engine/1.0.0")

    # ---- File metadata ----
    original_filename: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    content_type: Mapped[str] = mapped_column(String(64), nullable=False, default="image/png")
    file_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    image_width: Mapped[int] = mapped_column(nullable=False, default=0)
    image_height: Mapped[int] = mapped_column(nullable=False, default=0)
    psnr_db: Mapped[Optional[float]] = mapped_column(nullable=True)
    # Persisted watermarked image (PNG bytes). Allows the Wix client
    # to re-download the watermarked asset via GET /asset/{id}/image
    # without the original. Nullable so old rows from before this
    # column was added stay valid.
    watermarked_image: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)

    # ---- Evidence chain (ISO/IEC 27037 alignment) ----
    chain_of_custody_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ---- Composite + fuzzy indexes ----
    #
    # B-tree composites for compound lookups (Postgres + SQLite both honour these).
    __table_args__ = (
        Index("ix_ledger_account_created", "account_id", "created_at"),
        Index("ix_ledger_phash_account", "perceptual_hash_phash", "account_id"),
    )

    # NOTE: The GIN + pg_trgm index on perceptual_hash_phash is created in
    # schema.sql / Alembic migration 0002, not in SQLAlchemy DDL. We can't
    # declare it here because the `gin_trgm_ops` operator class is
    # Postgres-specific and would break SQLite DDL.

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dict."""
        return {
            "asset_id": str(self.asset_id),
            "payload_hex": self.payload_hex,
            "zkp_commitment_hex": self.zkp_commitment_hex,
            "perceptual_hashes": {
                "phash": self.perceptual_hash_phash,
                "dhash": self.perceptual_hash_dhash,
                "ahash": self.perceptual_hash_ahash,
                "whash": self.perceptual_hash_whash,
            },
            "c2pa": {
                "manifest_reference": self.c2pa_manifest_reference,
                "manifest_uuid": self.c2pa_manifest_uuid,
                "embedded": self.c2pa_embedded,
            },
            "creation_timestamp": self.creation_timestamp.isoformat() if self.creation_timestamp else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "account_id": self.account_id,
            "device_signature": self.device_signature,
            "generator_model_id": self.generator_model_id,
            "original_filename": self.original_filename,
            "content_type": self.content_type,
            "file_size_bytes": self.file_size_bytes,
            "image_width": self.image_width,
            "image_height": self.image_height,
            "psnr_db": self.psnr_db,
        }
