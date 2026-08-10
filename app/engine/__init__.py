"""
Engine layer: the math and crypto that makes DEEP-TRACE work.

- watermark   : DCT-QIM frequency-domain embedder/extractor
- perceptual  : robust image hashing for content matching
- zkp         : Pedersen cryptographic commitments (zk-friendly)
- c2pa        : C2PA manifest generation and validation
- prng        : key-derived pseudo-random number generator
- ecc         : Reed-Solomon error correction
"""

from app.engine.watermark import DCTQIMWatermark
from app.engine.perceptual import PerceptualHasher
from app.engine.zkp import PedersenCommitment
from app.engine.prng import KeyedPRNG

__all__ = [
    "DCTQIMWatermark",
    "PerceptualHasher",
    "PedersenCommitment",
    "KeyedPRNG",
]
