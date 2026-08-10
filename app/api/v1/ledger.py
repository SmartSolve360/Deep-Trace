"""
Ledger query endpoints.

Auth-required (X-API-Key):
  GET /api/v1/ledger/{asset_id}        single entry by id
  GET /api/v1/ledger                   paginated list (filter by account)
  GET /api/v1/ledger/search            perceptual-hash search

Public (no API key, rate-limited):
  GET /api/v1/asset/{asset_id}         public asset metadata
  GET /api/v1/asset/{asset_id}/image   watermarked PNG download
  GET /api/v1/asset/{asset_id}/thumb   low-res perceptual thumbnail
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.deps import get_ledger_service
from app.core.logging import get_logger
from app.engine.perceptual import PerceptualHasher, _hex_hamming
from app.schemas.asset import LedgerEntry, LedgerSearchResult
from app.services.auth import AuthService
from app.services.ledger import LedgerService

logger = get_logger(__name__)

router = APIRouter(prefix="/ledger", tags=["ledger"])


def _to_entry_dict(entry) -> dict:
    """Convert SQLAlchemy row to LedgerEntry-compatible dict."""
    d = entry.to_dict()
    return {
        "asset_id": d["asset_id"],
        "payload_hex": d["payload_hex"],
        "zkp_commitment_hex": d["zkp_commitment_hex"],
        "perceptual_hashes": d["perceptual_hashes"],
        "c2pa": d["c2pa"],
        "creation_timestamp": d["creation_timestamp"],
        "account_id": d["account_id"],
        "device_signature": d["device_signature"],
        "generator_model_id": d["generator_model_id"],
        "image_width": d["image_width"],
        "image_height": d["image_height"],
        "file_size_bytes": d["file_size_bytes"],
        "psnr_db": d["psnr_db"],
        "created_at": d["created_at"],
    }


@router.get(
    "/search",
    response_model=list[LedgerSearchResult],
    summary="Search ledger by perceptual hash (pHash or dHash) -- API key required",
)
async def search_ledger(
    phash: Optional[str] = Query(default=None, min_length=8, max_length=64, description="pHash hex string"),
    dhash: Optional[str] = Query(default=None, min_length=8, max_length=64, description="dHash hex string"),
    account_id: Optional[str] = Query(default=None, max_length=128),
    limit: int = Query(default=10, ge=1, le=50),
    max_distance: int = Query(default=10, ge=0, le=64, description="Max bit distance"),
    api_key: str = Depends(AuthService.require_api_key),
    ledger: LedgerService = Depends(get_ledger_service),
) -> list[LedgerSearchResult]:
    # NOTE: must be defined BEFORE the /{asset_id} catch-all below, otherwise
    # FastAPI's routing matches "search" as an asset_id and rejects it as
    # not-a-UUID.
    if not phash and not dhash:
        raise HTTPException(
            status_code=400,
            detail="Provide either `phash` or `dhash` (or both).",
        )

    seen: set[str] = set()
    merged: list[tuple[Any, dict[str, int]]] = []

    if phash:
        for entry, dist in await ledger.search_by_phash(
            phash, account_id=account_id, limit=limit, max_distance=max_distance
        ):
            aid = str(entry.asset_id)
            if aid in seen:
                continue
            seen.add(aid)
            merged.append((entry, {"phash": dist, "dhash": 0, "ahash": 0, "whash": 0}))

    if dhash:
        for entry, dist in await ledger.search_by_dhash(
            dhash, account_id=account_id, limit=limit, max_distance=max_distance
        ):
            aid = str(entry.asset_id)
            if aid in seen:
                # Replace the dHash=0 stub with the real distance
                for i, (e, d) in enumerate(merged):
                    if str(e.asset_id) == aid:
                        d["dhash"] = dist
                        merged[i] = (e, d)
                        break
            else:
                seen.add(aid)
                merged.append(
                    (entry, {"phash": 0, "dhash": dist, "ahash": 0, "whash": 0})
                )

    out: list[LedgerSearchResult] = []
    for entry, distances in merged[:limit]:
        out.append(
            LedgerSearchResult(
                asset_id=str(entry.asset_id),
                account_id=entry.account_id,
                creation_timestamp=entry.creation_timestamp,
                perceptual_hashes={
                    "phash": entry.perceptual_hash_phash,
                    "dhash": entry.perceptual_hash_dhash,
                    "ahash": entry.perceptual_hash_ahash,
                    "whash": entry.perceptual_hash_whash,
                },
                perceptual_distance=distances,
                payload_match=False,
            )
        )
    return out


@router.get(
    "/{asset_id}",
    response_model=LedgerEntry,
    summary="Get a single ledger entry by asset_id",
)
async def get_entry(
    asset_id: str,
    api_key: str = Depends(AuthService.require_api_key),
    ledger: LedgerService = Depends(get_ledger_service),
) -> LedgerEntry:
    try:
        uuid.UUID(asset_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="asset_id must be a UUID")

    entry = await ledger.get_by_id(asset_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return LedgerEntry(**_to_entry_dict(entry))


@router.get(
    "",
    response_model=list[LedgerEntry],
    summary="List ledger entries (paginated, optionally filtered by account)",
)
async def list_entries(
    account_id: Optional[str] = Query(default=None, max_length=128),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key: str = Depends(AuthService.require_api_key),
    ledger: LedgerService = Depends(get_ledger_service),
) -> list[LedgerEntry]:
    if account_id:
        entries = await ledger.list_for_account(account_id, limit=limit, offset=offset)
    else:
        entries = await ledger.list_all(limit=limit, offset=offset)
    return [LedgerEntry(**_to_entry_dict(e)) for e in entries]
