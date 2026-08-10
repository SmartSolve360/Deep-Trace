"""
Ledger service — the only module that talks to the asset_provenance_ledger.

All database operations are async, transactional, and use the request-scoped
session from the `get_db` dependency. The service is intentionally stateless
so multiple workers can share it.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime
from typing import Optional, Sequence

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.engine.perceptual import PerceptualHashes, _hex_hamming
from app.models.asset import AssetProvenanceLedger

logger = get_logger(__name__)

# Postgres-only dialects; we sniff via the DSN to decide whether the
# hamming_hex() function + GIN index are available.
_POSTGRES_DIALECTS = frozenset({"postgresql", "postgres"})


class LedgerService:
    """Async CRUD over the provenance ledger."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # ------------------------------------------------------------------
    # Dialect detection
    # ------------------------------------------------------------------

    @property
    def _is_postgres(self) -> bool:
        """True if the bound engine is Postgres (or compatible)."""
        bind = self.session.get_bind()
        dialect = getattr(bind, "dialect", None)
        if dialect is None:
            return False
        return dialect.name in _POSTGRES_DIALECTS

    async def _function_exists(self, name: str) -> bool:
        """Probe for the existence of a database function (Postgres only)."""
        if not self._is_postgres:
            return False
        result = await self.session.execute(
            text("SELECT 1 FROM pg_proc WHERE proname = :n LIMIT 1"),
            {"n": name},
        )
        return result.scalar() is not None

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    async def register(
        self,
        *,
        payload_hex: str,
        zkp_commitment_hex: str,
        zkp_opening_value: Optional[str],
        zkp_opening_randomness: Optional[str],
        perceptual_hashes: PerceptualHashes,
        c2pa_manifest_reference: Optional[str],
        c2pa_manifest_uuid: Optional[str],
        c2pa_embedded: bool,
        creation_timestamp: datetime,
        account_id: str,
        account_public_key: str,
        device_signature: str,
        generator_model_id: str,
        original_filename: Optional[str],
        content_type: str,
        file_size_bytes: int,
        image_width: int,
        image_height: int,
        psnr_db: Optional[float],
        watermarked_image: Optional[bytes] = None,
        notes: Optional[str] = None,
    ) -> AssetProvenanceLedger:
        """Insert a new ledger entry. Returns the persisted row."""
        chain_hash = self._compute_chain_hash(
            payload_hex,
            zkp_commitment_hex,
            perceptual_hashes,
            creation_timestamp,
            account_id,
        )
        entry = AssetProvenanceLedger(
            asset_id=uuid.uuid4(),
            payload_hex=payload_hex,
            zkp_commitment_hex=zkp_commitment_hex,
            zkp_opening_value=zkp_opening_value,
            zkp_opening_randomness=zkp_opening_randomness,
            perceptual_hash_phash=perceptual_hashes.phash,
            perceptual_hash_dhash=perceptual_hashes.dhash,
            perceptual_hash_ahash=perceptual_hashes.ahash,
            perceptual_hash_whash=perceptual_hashes.whash,
            c2pa_manifest_reference=c2pa_manifest_reference,
            c2pa_manifest_uuid=c2pa_manifest_uuid,
            c2pa_embedded=c2pa_embedded,
            creation_timestamp=creation_timestamp,
            account_id=account_id,
            account_public_key=account_public_key,
            device_signature=device_signature,
            generator_model_id=generator_model_id,
            original_filename=original_filename,
            content_type=content_type,
            file_size_bytes=file_size_bytes,
            image_width=image_width,
            image_height=image_height,
            psnr_db=psnr_db,
            watermarked_image=watermarked_image,
            chain_of_custody_hash=chain_hash,
            notes=notes,
        )
        self.session.add(entry)
        await self.session.flush()
        await self.session.refresh(entry)
        logger.info(
            "ledger.registered",
            asset_id=str(entry.asset_id),
            account_id=account_id,
            payload_hex=payload_hex[:16] + "...",
            has_image=watermarked_image is not None,
        )
        return entry

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def get_by_id(self, asset_id: uuid.UUID | str) -> Optional[AssetProvenanceLedger]:
        """Fetch a single ledger entry by asset_id."""
        if isinstance(asset_id, str):
            asset_id = uuid.UUID(asset_id)
        result = await self.session.execute(
            select(AssetProvenanceLedger).where(AssetProvenanceLedger.asset_id == asset_id)
        )
        return result.scalar_one_or_none()

    async def get_by_commitment(self, commitment_hex: str) -> Optional[AssetProvenanceLedger]:
        """Fetch a single ledger entry by its Pedersen commitment."""
        result = await self.session.execute(
            select(AssetProvenanceLedger).where(AssetProvenanceLedger.zkp_commitment_hex == commitment_hex)
        )
        return result.scalar_one_or_none()

    async def get_by_payload(self, payload_hex: str) -> Sequence[AssetProvenanceLedger]:
        """All ledger entries matching a payload hex (typically 0 or 1)."""
        result = await self.session.execute(
            select(AssetProvenanceLedger)
            .where(AssetProvenanceLedger.payload_hex == payload_hex)
            .order_by(AssetProvenanceLedger.created_at.desc())
        )
        return result.scalars().all()

    async def list_for_account(self, account_id: str, limit: int = 100, offset: int = 0) -> Sequence[AssetProvenanceLedger]:
        """Paginated history for one account."""
        result = await self.session.execute(
            select(AssetProvenanceLedger)
            .where(AssetProvenanceLedger.account_id == account_id)
            .order_by(AssetProvenanceLedger.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return result.scalars().all()

    async def list_all(self, limit: int = 100, offset: int = 0) -> Sequence[AssetProvenanceLedger]:
        """Global list of recent ledger entries (no account filter)."""
        result = await self.session.execute(
            select(AssetProvenanceLedger)
            .order_by(AssetProvenanceLedger.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return result.scalars().all()

    async def search_by_phash(
        self,
        phash: str,
        *,
        account_id: Optional[str] = None,
        limit: int = 20,
        max_distance: int = 10,
    ) -> list[tuple[AssetProvenanceLedger, int]]:
        """Fuzzy search on `perceptual_hash_phash` (DCT-based)."""
        return await self._search_hash(
            "perceptual_hash_phash", phash,
            account_id=account_id, limit=limit, max_distance=max_distance,
        )

    async def search_by_dhash(
        self,
        dhash: str,
        *,
        account_id: Optional[str] = None,
        limit: int = 20,
        max_distance: int = 8,
    ) -> list[tuple[AssetProvenanceLedger, int]]:
        """Fuzzy search on `perceptual_hash_dhash` (gradient-based)."""
        return await self._search_hash(
            "perceptual_hash_dhash", dhash,
            account_id=account_id, limit=limit, max_distance=max_distance,
        )

    async def _search_hash(
        self,
        column_name: str,
        hash_hex: str,
        *,
        account_id: Optional[str],
        limit: int,
        max_distance: int,
    ) -> list[tuple[AssetProvenanceLedger, int]]:
        """
        Find ledger entries whose perceptual hash is within `max_distance`
        bits of the query. Returns a list of (entry, hamming_distance)
        tuples sorted by distance ascending.

        Strategy A — Postgres with the GIN + pg_trgm index:
            1. Use trigram similarity to fetch a candidate set whose
               hash is textually similar to the query (cheap, scales)
            2. Compute exact Hamming distance via the hamming_hex() SQL
               function
            3. Filter by max_distance and return top-`limit` by distance

        Strategy B — SQLite / fallback:
            1. Full scan with optional account filter
            2. In-Python Hamming distance ranking
        """
        if not hash_hex or not re.match(r"^[0-9a-fA-F]+$", hash_hex):
            return []

        column = getattr(AssetProvenanceLedger, column_name)

        if self._is_postgres and await self._function_exists("hamming_hex"):
            return await self._search_indexed(
                column, hash_hex,
                account_id=account_id, limit=limit, max_distance=max_distance,
            )
        return await self._search_fallback(
            column, hash_hex,
            account_id=account_id, limit=limit,
        )

    async def _search_indexed(
        self,
        column,
        hash_hex: str,
        *,
        account_id: Optional[str],
        limit: int,
        max_distance: int,
    ) -> list[tuple[AssetProvenanceLedger, int]]:
        """Postgres + GIN strategy. trigram candidates + hamming_hex ranking."""
        dist_col = func.hamming_hex(column, hash_hex).label("dist")
        stmt = (
            select(AssetProvenanceLedger, dist_col)
            .where(column.op("%)")(hash_hex))
            .where(dist_col <= max_distance)
            .order_by(dist_col.asc())
            .limit(limit)
        )
        if account_id is not None:
            stmt = stmt.where(AssetProvenanceLedger.account_id == account_id)
        result = await self.session.execute(stmt)
        return [(row[0], int(row[1])) for row in result.all()]

    async def _search_fallback(
        self,
        column,
        hash_hex: str,
        *,
        account_id: Optional[str],
        limit: int,
    ) -> list[tuple[AssetProvenanceLedger, int]]:
        """Portable fallback for SQLite / pre-migration Postgres. O(N) scan."""
        stmt = select(AssetProvenanceLedger)
        if account_id is not None:
            stmt = stmt.where(AssetProvenanceLedger.account_id == account_id)
        result = await self.session.execute(stmt)
        candidates = result.scalars().all()
        scored = sorted(
            candidates,
            key=lambda e: _hex_hamming(getattr(e, column.key), hash_hex),
        )
        return [
            (entry, _hex_hamming(getattr(entry, column.key), hash_hex))
            for entry in scored[:limit]
        ]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_chain_hash(
        payload_hex: str,
        commitment_hex: str,
        hashes: PerceptualHashes,
        creation_timestamp: datetime,
        account_id: str,
    ) -> str:
        """
        ISO/IEC 27037 chain-of-custody hash: SHA-256 over the canonical
        serialisation of the binding tuple. Stored so any subsequent
        modification of the row can be detected.
        """
        h = hashes.to_dict()
        canonical = "|".join(
            [
                payload_hex,
                commitment_hex,
                h.get("phash", ""),
                h.get("dhash", ""),
                h.get("ahash", ""),
                h.get("whash", ""),
                creation_timestamp.isoformat(),
                account_id,
            ]
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
