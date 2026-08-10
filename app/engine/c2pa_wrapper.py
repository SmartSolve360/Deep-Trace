"""
C2PA manifest generation and validation.

C2PA (Content Credentials) is the open standard from the Coalition for
Content Provenance and Authenticity. We generate a manifest that
asserts:

    - software agent:   DEEP-TRACE Engine v1.0
    - account binding:  account_id (hashed for privacy)
    - creation event:   timestamp, device signature
    - reference:        perceptual hashes, asset_id, payload hex

Signing modes
-------------
1. **Real signed C2PA** — when the `c2pa-python` library is installed
   AND a properly-issued signing cert + key are provided via
   `C2PA_SIGNING_KEY_PATH` / `C2PA_SIGNING_CERT_PATH`, the wrapper
   produces a real C2PA store. The cert MUST be C2PA-trust-list-issued
   (e.g. by the CAI/Adobe trust list) — c2pa-rs performs strict chain
   validation and rejects self-signed dev certs with
   "the certificate is invalid".

2. **Reference-only** — when c2pa-python is missing, or when real
   signing fails (e.g. dev cert), the wrapper emits a structured
   reference (UUID + JSON assertion) that the ledger records. The
   downstream forensic workflow can still match the asset by
   perceptual hash / payload; only the C2PA Content Credentials
   assertion is missing. The fallback is logged at WARN level.

The real-signing attempt is non-fatal: a cert validation failure
degrades to the reference-only path so the service stays available
in dev/test.
"""

from __future__ import annotations

import io
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from app.core.logging import get_logger

logger = get_logger(__name__)

try:
    # c2pa-python is the official Python SDK from the CAI.
    # https://github.com/contentauth/c2pa-python
    import c2pa  # type: ignore

    _C2PA_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    _C2PA_AVAILABLE = False
    logger.warn("c2pa.unavailable", detail="c2pa-python not installed; using reference-only mode")


@dataclass
class C2PAManifest:
    """Result of generating a C2PA manifest."""

    manifest_uuid: str
    embedded: bool
    reference: str
    raw_manifest: dict[str, Any]


class C2PAWrapper:
    """
    Thin wrapper over c2pa-python (when available) plus a manifest-reference
    fallback that always returns a usable reference for the ledger.
    """

    def __init__(
        self,
        signing_key_path: Optional[str] = None,
        signing_cert_path: Optional[str] = None,
    ) -> None:
        self.signing_key_path = signing_key_path
        self.signing_cert_path = signing_cert_path
        # Eagerly probe signing viability so we log once at startup
        # rather than per-embed.
        self._signing_viable = self._probe_signing_viability()

    def _probe_signing_viability(self) -> bool:
        """Return True if c2pa signing can be attempted (lib + files)."""
        if not _C2PA_AVAILABLE:
            return False
        if not self.signing_key_path or not self.signing_cert_path:
            return False
        if not os.path.isfile(self.signing_key_path):
            logger.warn("c2pa.signing.key_missing", path=self.signing_key_path)
            return False
        if not os.path.isfile(self.signing_cert_path):
            logger.warn("c2pa.signing.cert_missing", path=self.signing_cert_path)
            return False
        return True

    # ------------------------------------------------------------------
    # Manifest generation
    # ------------------------------------------------------------------

    def generate_manifest(
        self,
        *,
        account_id: str,
        asset_id: str,
        payload_hex: str,
        perceptual_hashes: dict[str, str],
        device_sig: str,
        timestamp: float,
    ) -> C2PAManifest:
        """
        Build a C2PA manifest for the given provenance data.

        Tries real signed C2PA first; on any failure (lib missing, cert
        invalid, c2pa-rs strict rejection) falls back to the
        reference-only mode. Never raises.
        """
        manifest_uuid = str(uuid.uuid4())
        ts_iso = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()

        # The structured assertion is always produced so the ledger can
        # store meaningful provenance data even in fallback mode.
        assertion: dict[str, Any] = {
            "asset_id": asset_id,
            "account_id_hash": _hash_for_manifest(account_id),
            "payload_hex": payload_hex,
            "perceptual_hashes": perceptual_hashes,
            "device_signature": device_sig,
            "creation_timestamp": ts_iso,
            "generator": {
                "name": "DEEP-TRACE Engine",
                "version": "1.0.0",
                "agent_type": "watermarker",
            },
        }

        # ---- Real C2PA signing path ----
        signed = self._try_real_signing(manifest_uuid, assertion)
        if signed is not None:
            return signed

        # ---- Reference-only fallback ----
        if self._signing_viable:
            # We tried and failed -- tell the operator why
            logger.warn(
                "c2pa.signing.fallback",
                detail="Real C2PA signing failed; emitting reference-only manifest. "
                "This is expected for self-signed dev certs -- production deployments "
                "need a C2PA trust-list-issued cert.",
                manifest_uuid=manifest_uuid,
            )
        return C2PAManifest(
            manifest_uuid=manifest_uuid,
            embedded=False,
            reference=f"deep-trace://manifest/{manifest_uuid}",
            raw_manifest={"fallback": True, "assertion": assertion},
        )

    def _try_real_signing(
        self,
        manifest_uuid: str,
        assertion: dict[str, Any],
    ) -> Optional[C2PAManifest]:
        """
        Attempt to produce a real C2PA-signed manifest.

        Returns the manifest on success, or None on any failure
        (silent fallback to reference-only mode).
        """
        if not self._signing_viable:
            return None

        try:
            cert_pem = _read_pem(self.signing_cert_path)
            key_pem = _read_pem(self.signing_key_path)
        except OSError as exc:
            logger.warn("c2pa.signing.read_failed", error=str(exc))
            return None

        try:
            # Build C2paSignerInfo: EC P-256 (ES256) is the most
            # widely-supported algorithm. If the cert is RSA,
            # c2pa_signer_info_check will fail; we fall back.
            info = c2pa.C2paSignerInfo(  # type: ignore[name-defined]
                alg=c2pa.C2paSigningAlg.ES256,  # type: ignore[name-defined]
                sign_cert=cert_pem,
                private_key=key_pem,
                ta_url=None,
            )
            signer = c2pa.Signer.from_info(info)  # type: ignore[name-defined]
        except Exception as exc:
            logger.warn("c2pa.signing.signer_construct_failed", error=str(exc))
            return None

        try:
            # Build the manifest as a JSON-serialised dict for the
            # builder. c2pa.Builder accepts a dict or JSON string.
            manifest_json = {
                "@context": "https://c2pa.org/schemas/v1",
                "manifest_uuid": manifest_uuid,
                "claim_generator": "DEEP-TRACE Engine/1.0.0",
                "assertions": [
                    {
                        "label": "deep-trace.assertion",
                        "data": assertion,
                    }
                ],
            }
            # c2pa.Builder needs an image to attach the manifest to.
            # We sign a minimal 1x1 PNG to produce the signed manifest
            # bytes; the actual asset embedding happens elsewhere.
            placeholder_png = _MINIMAL_PNG
            builder = c2pa.Builder(manifest_json)  # type: ignore[name-defined]
            signed_stream = builder.sign(  # type: ignore[name-defined]
                signer,
                "image/png",
                io.BytesIO(placeholder_png),
                io.BytesIO(),
            )
            signed_bytes = (
                signed_stream.getvalue()
                if hasattr(signed_stream, "getvalue")
                else signed_stream
            )
        except Exception as exc:
            # This is the expected path for self-signed dev certs --
            # c2pa-rs rejects them with "Signature: the certificate is
            # invalid". Log at debug (not warn) since the warning has
            # already been emitted at the higher level.
            logger.debug("c2pa.signing.embed_failed", error=str(exc))
            return None

        # Persist the signed manifest for forensic retrieval
        ref_path = f"manifests/{manifest_uuid}.c2pa"
        try:
            os.makedirs("manifests", exist_ok=True)
            with open(ref_path, "wb") as f:
                f.write(signed_bytes)
        except OSError as exc:
            logger.warn("c2pa.manifest.persist_failed", path=ref_path, error=str(exc))

        logger.info("c2pa.manifest.signed", path=ref_path, uuid=manifest_uuid, bytes=len(signed_bytes))
        return C2PAManifest(
            manifest_uuid=manifest_uuid,
            embedded=True,
            reference=ref_path,
            raw_manifest={
                "signed": True,
                "manifest_uuid": manifest_uuid,
                "size_bytes": len(signed_bytes),
                "assertion": assertion,
            },
        )

    # ------------------------------------------------------------------
    # Manifest validation
    # ------------------------------------------------------------------

    def validate_reference(self, reference: str) -> Optional[dict[str, Any]]:
        """
        Read a manifest back from its reference. Returns None if the
        reference can't be resolved (e.g. fallback URL).
        """
        if not reference or reference.startswith("deep-trace://"):
            return None
        try:
            with open(reference, "rb") as f:
                return {"raw_bytes": f.read(), "format": "c2pa"}
        except FileNotFoundError:
            logger.warn("c2pa.manifest.missing", path=reference)
            return None
        except Exception as exc:  # pragma: no cover
            logger.error("c2pa.manifest.read_failed", path=reference, error=str(exc))
            return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_pem(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _hash_for_manifest(value: str) -> str:
    """Stable SHA-256 prefix of a value for inclusion in the manifest."""
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


# Minimal 1x1 PNG (transparent) used as a placeholder for c2pa.Builder
# to attach a signed manifest to. The actual asset embedding happens
# at a higher layer.
_MINIMAL_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000d49444154789c6300010000000500010d0a2db40000000049454e44ae42"
    "60820000"
)
