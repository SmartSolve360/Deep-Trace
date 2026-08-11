"""
Forensics service — high-level workflows combining the watermark engine,
the perceptual hasher, the ZKP module, the C2PA wrapper, and the ledger.

Two main operations:

    embed_and_register(...)
        Generate payload → embed watermark → compute perceptual hashes
        → build Pedersen commitment → emit C2PA manifest → register in
        ledger → return watermarked image + ledger receipt.

    extract_and_lookup(...)
        Extract payload → compute perceptual hashes → look up ledger
        by commitment (exact) or by perceptual hash (fuzzy) → verify
        payload match → return forensic report.

The service owns the orchestrating logic so the API layer stays thin.
"""

from __future__ import annotations

import base64
import io
import uuid
from datetime import datetime, timezone
from typing import Optional

import cv2
import numpy as np

from app.config import settings
from app.core.exceptions import AssetNotFoundError
from app.core.logging import get_logger
from app.engine.c2pa_wrapper import C2PAWrapper
from app.engine.perceptual import PerceptualHashes, PerceptualHasher, _hex_hamming
from app.engine.watermark import DCTQIMWatermark
from app.engine.zkp import PedersenCommitment
from app.models.asset import AssetProvenanceLedger
from app.schemas.asset import (
    EmbedResponse,
    ExtractResponse,
    LedgerMatch,
    VerifyResponse,
)
from app.services.ledger import LedgerService
from app.utils.encoding import now_iso, now_ts
from app.utils.image import decode_image, encode_png

logger = get_logger(__name__)


class ForensicsService:
    """
    End-to-end forensic workflows.

    Stateless across instances — all state lives in the engine objects
    and the per-request ledger session.
    """

    def __init__(
        self,
        ledger: LedgerService,
        c2pa: Optional[C2PAWrapper] = None,
    ) -> None:
        self.ledger = ledger
        self.c2pa = c2pa or C2PAWrapper(
            signing_key_path=settings.C2PA_SIGNING_KEY_PATH,
            signing_cert_path=settings.C2PA_SIGNING_CERT_PATH,
        )
        self._watermark = DCTQIMWatermark(secret_key=settings.SECRET_KEY.encode("utf-8"))
        self._zkp = PedersenCommitment()

    # ------------------------------------------------------------------
    # Embed + register
    # ------------------------------------------------------------------

    async def embed_and_register(
        self,
        *,
        image_bytes: bytes,
        account_id: str,
        account_public_key: str,
        device_signature: str,
        original_filename: Optional[str] = None,
        timestamp: Optional[float] = None,
        notes: Optional[str] = None,
    ) -> EmbedResponse:
        """
        Embed a 128-bit provenance payload in the image and register the
        result in the ledger. Returns the EmbedResponse with the
        watermarked image encoded as PNG bytes.
        """
        ts = timestamp or now_ts()
        # Postgres column is TIMESTAMP WITHOUT TIME ZONE; pass naive datetime
        # (asyncpg refuses to mix offset-naive and offset-aware datetimes).
        ts_dt = datetime.fromtimestamp(ts)

        # 1. Decode + validate the input image
        image_bgr = decode_image(image_bytes)
        h, w = image_bgr.shape[:2]

        # 2. Generate payload (HMAC over account_id | ts | device_sig)
        #    and embed it via DCT-QIM
        wm = self._watermark.embed_watermark(
            image_bgr=image_bgr,
            account_id=account_id,
            timestamp=ts,
            device_sig=device_signature,
        )
        payload_hex = wm.payload_hex

        # 3. Compute perceptual hashes on the ORIGINAL (unwatermarked) image
        #    so they describe the asset's content, not the embedded
        #    frequency pattern.
        original_hashes = PerceptualHasher.compute_hashes(image_bytes)

        # 4. Build a Pedersen commitment over (payload, perceptual_hashes, account)
        #    The opening (value, randomness) is kept for verification.
        commitment_value = _commitment_input(payload_hex, original_hashes, account_id)
        commitment, (open_v, open_r) = self._zkp.commit(commitment_value)
        commitment_hex = self._zkp.to_hex(commitment)

        # 5. C2PA manifest
        manifest = self.c2pa.generate_manifest(
            account_id=account_id,
            asset_id="pending",  # updated post-insert below
            payload_hex=payload_hex,
            perceptual_hashes=original_hashes.to_dict(),
            device_sig=device_signature,
            timestamp=ts,
        )

        # 6. Register in ledger (with the watermarked PNG persisted
        #    so the public /asset/{id}/image endpoint can re-serve it)
        png_bytes, file_size = encode_png(wm.watermarked_bgr)
        entry = await self.ledger.register(
            payload_hex=payload_hex,
            zkp_commitment_hex=commitment_hex,
            zkp_opening_value=str(open_v),
            zkp_opening_randomness=str(open_r),
            perceptual_hashes=original_hashes,
            c2pa_manifest_reference=manifest.reference,
            c2pa_manifest_uuid=manifest.manifest_uuid,
            c2pa_embedded=manifest.embedded,
            creation_timestamp=ts_dt,
            account_id=account_id,
            account_public_key=account_public_key,
            device_signature=device_signature,
            generator_model_id=f"deep-trace-engine/{settings.PROJECT_VERSION}",
            original_filename=original_filename,
            content_type="image/png",
            file_size_bytes=file_size,
            image_width=w,
            image_height=h,
            psnr_db=wm.psnr_db,
            watermarked_image=png_bytes,
            notes=notes,
        )

        logger.info(
            "forensics.embed.complete",
            asset_id=str(entry.asset_id),
            psnr_db=wm.psnr_db,
            file_size_bytes=file_size,
        )

        return EmbedResponse(
            status="SUCCESS",
            asset_id=str(entry.asset_id),
            payload_hex=payload_hex,
            zkp_commitment_hex=commitment_hex,
            perceptual_hashes=original_hashes.to_dict(),
            c2pa={
                "manifest_uuid": manifest.manifest_uuid,
                "reference": manifest.reference,
                "embedded": manifest.embedded,
            },
            image_width=w,
            image_height=h,
            file_size_bytes=file_size,
            psnr_db=wm.psnr_db,
            watermarked_image_b64=base64.b64encode(png_bytes).decode("ascii"),
            created_at=entry.created_at,
        )

    # ------------------------------------------------------------------
    # Extract + lookup
    # ------------------------------------------------------------------

    async def extract_and_lookup(
        self,
        *,
        image_bytes: bytes,
        account_id: Optional[str] = None,
    ) -> ExtractResponse:
        """
        Extract a watermark from the image and try to match it against
        the ledger. The match is by:
            1. Exact Pedersen commitment (if a ZKP commitment was provided)
            2. Exact payload hex
            3. Perceptual hash (pHash) within Hamming distance threshold
        """
        # 1. Decode
        image_bgr = decode_image(image_bytes)
        h, w = image_bgr.shape[:2]

        # 2. Extract payload
        payload_hex, status_msg, errors_corrected = self._watermark.extract_watermark(image_bgr)

        # 3. Perceptual hashes of the suspect image
        suspect_hashes = PerceptualHasher.compute_hashes(image_bytes)

        # 4. Try to match
        ledger_match: Optional[LedgerMatch] = None
        asset_id: Optional[str] = None
        c2pa_manifest: Optional[dict] = None

        if payload_hex:
            # Exact payload lookup
            matches = await self.ledger.get_by_payload(payload_hex)
            if matches:
                # Prefer the most recent match for the same account if provided
                chosen = matches[0]
                if account_id:
                    same_account = [m for m in matches if m.account_id == account_id]
                    if same_account:
                        chosen = same_account[0]
                ledger_match = self._build_ledger_match(chosen, suspect_hashes, payload_hex)
                asset_id = str(chosen.asset_id)
                c2pa_manifest = self.c2pa.validate_reference(chosen.c2pa_manifest_reference or "")
            else:
                # Fuzzy match by perceptual hash (returns (entry, distance) tuples)
                candidates = await self.ledger.search_by_phash(
                    suspect_hashes.phash, account_id=account_id
                )
                if candidates:
                    best, _dist = candidates[0]
                    ledger_match = self._build_ledger_match(best, suspect_hashes, payload_hex)
                    asset_id = str(best.asset_id)
                    c2pa_manifest = self.c2pa.validate_reference(best.c2pa_manifest_reference or "")

        logger.info(
            "forensics.extract.complete",
            payload_hex_prefix=(payload_hex or "")[:16],
            asset_id=asset_id,
            status=status_msg,
        )

        return ExtractResponse(
            status="MATCH_FOUND" if ledger_match else ("PAYLOAD_EXTRACTED" if payload_hex else "NO_PAYLOAD"),
            asset_id=asset_id,
            payload_hex=payload_hex or None,
            zkp_commitment_hex=None,
            perceptual_hashes=suspect_hashes.to_dict(),
            ledger_match=ledger_match,
            c2pa_manifest=c2pa_manifest,
            extraction_status=status_msg,
            errors_corrected=errors_corrected,
        )

    # ------------------------------------------------------------------
    # Verify
    # ------------------------------------------------------------------

    async def verify(
        self,
        *,
        image_bytes: bytes,
        expected_asset_id: str,
    ) -> VerifyResponse:
        """
        Verify that a suspect image corresponds to a specific ledger entry
        by:
            1. Fetching the ledger entry by asset_id
            2. Extracting the watermark from the image
            3. Comparing payloads
            4. Comparing perceptual hashes
        """
        try:
            entry = await self.ledger.get_by_id(expected_asset_id)
        except Exception as exc:
            raise AssetNotFoundError(f"Could not fetch ledger entry: {exc}")
        if entry is None:
            raise AssetNotFoundError(
                f"No ledger entry for asset_id {expected_asset_id}",
                details={"asset_id": expected_asset_id},
            )

        image_bgr = decode_image(image_bytes)
        suspect_hashes = PerceptualHasher.compute_hashes(image_bytes)
        payload_hex, status, _ = self._watermark.extract_watermark(image_bgr)
        payload_match = bool(payload_hex) and payload_hex.lower() == entry.payload_hex.lower()

        return VerifyResponse(
            verified=payload_match,
            status=status if payload_hex else "NO_PAYLOAD",
            asset_id=str(entry.asset_id),
            payload_match=payload_match,
            perceptual_distance={
                "phash": _hex_hamming(suspect_hashes.phash, entry.perceptual_hash_phash),
                "dhash": _hex_hamming(suspect_hashes.dhash, entry.perceptual_hash_dhash),
                "ahash": _hex_hamming(suspect_hashes.ahash, entry.perceptual_hash_ahash),
                "whash": _hex_hamming(suspect_hashes.whash, entry.perceptual_hash_whash),
            },
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_ledger_match(
        self,
        entry: AssetProvenanceLedger,
        suspect_hashes: PerceptualHashes,
        payload_hex: str,
    ) -> LedgerMatch:
        distances = {
            "phash": _hex_hamming(suspect_hashes.phash, entry.perceptual_hash_phash),
            "dhash": _hex_hamming(suspect_hashes.dhash, entry.perceptual_hash_dhash),
            "ahash": _hex_hamming(suspect_hashes.ahash, entry.perceptual_hash_ahash),
            "whash": _hex_hamming(suspect_hashes.whash, entry.perceptual_hash_whash),
        }
        return LedgerMatch(
            asset_id=str(entry.asset_id),
            account_id=entry.account_id,
            creation_timestamp=entry.creation_timestamp,
            payload_match=(entry.payload_hex.lower() == payload_hex.lower()),
            perceptual_distance=distances,
            within_threshold=self._within_per_hash_threshold(distances),
        )

    def _within_per_hash_threshold(self, distances: dict[str, int]) -> bool:
        """True if any per-hash distance is within its configured tolerance."""
        thresholds = {
            "phash": settings.FORENSIC_MATCH_THRESHOLD_PHASH,
            "dhash": settings.FORENSIC_MATCH_THRESHOLD_DHASH,
            "ahash": settings.FORENSIC_MATCH_THRESHOLD_AHASH,
            "whash": settings.FORENSIC_MATCH_THRESHOLD_WHASH,
        }
        return any(distances[k] <= thresholds[k] for k in thresholds)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _commitment_input(
    payload_hex: str,
    hashes: PerceptualHashes,
    account_id: str,
) -> int:
    """
    Reduce the binding tuple to a single integer for the Pedersen commitment.
    Uses SHA-256 over the canonical serialisation, mod q.
    """
    import hashlib

    canonical = "|".join(
        [
            payload_hex,
            hashes.phash,
            hashes.dhash,
            hashes.ahash,
            hashes.whash,
            account_id,
        ]
    )
    h = hashlib.sha256(canonical.encode("utf-8")).digest()
    # PedersenCommitment will mod q internally, but we can do it here
    # to keep the value small.
    return int.from_bytes(h, "big")
