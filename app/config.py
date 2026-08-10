"""
Application settings — pydantic-settings, loaded from environment.

In production, every value must be injected via env vars or a `.env` file
loaded by Docker Compose. Defaults here are for local development only.
"""

from functools import lru_cache
from typing import Annotated, List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    """Strongly-typed application configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ---- Identity ----
    PROJECT_NAME: str = "DEEP-TRACE Engine"
    PROJECT_VERSION: str = "1.0.0"
    ENVIRONMENT: str = Field(default="development")
    API_V1_PREFIX: str = "/api/v1"

    # ---- Security ----
    # 32-byte minimum secret. Override in production via DEEPTRACE_SECRET_KEY.
    SECRET_KEY: str = Field(
        default="dev_only_change_me_in_production_32b!",
        min_length=32,
        description="Master HMAC secret. Derive sub-keys via HKDF.",
    )
    # NoDecode: accept plain comma-separated string in env (newer
    # pydantic-settings tries to JSON-decode list-typed env values
    # by default, which breaks the simple "key1,key2" syntax).
    API_KEYS: Annotated[List[str], NoDecode] = Field(
        default_factory=lambda: ["dev_api_key_change_me_in_production"],
        description="Allowed service-to-service API keys (comma-separated in env).",
    )
    CHALLENGE_TTL_SECONDS: int = 300
    NONCE_TTL_SECONDS: int = 600

    # ---- Database ----
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://postgres:postgres@db:5432/deeptrace",
        description="Async SQLAlchemy DSN. Use postgresql+asyncpg for async engine.",
    )
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20
    DATABASE_ECHO: bool = False

    # ---- C2PA ----
    C2PA_SIGNING_KEY_PATH: Optional[str] = None
    C2PA_SIGNING_CERT_PATH: Optional[str] = None
    C2PA_TRUST_ANCHORS_PATH: Optional[str] = None

    # ---- Watermark ----
    WATERMARK_MIN_IMAGE_SIZE: int = 128
    WATERMARK_MAX_IMAGE_SIZE: int = 4096
    WATERMARK_QIM_DELTA: float = 20.0
    WATERMARK_ECC_SYMBOLS: int = 32  # Reed-Solomon parity bytes (corrects 16 byte errors)

    # ---- Forensic search thresholds (bit-Hamming distance) ----
    # Higher distance = more permissive match. The pHash / dHash / aHash /
    # wHash columns are 64 bits, so distances are in [0, 64].
    #
    #   pHash: most robust to scaling/colour shift → higher tolerance
    #   dHash: gradient-based, sensitive to crops → lower tolerance
    #   aHash: average hash, sensitive to brightness → lower tolerance
    #   wHash: wavelet, balanced → medium tolerance
    #
    # Tighter thresholds reduce false positives (better for legal evidence);
    # looser thresholds improve recall (better for social-media forensics).
    FORENSIC_MATCH_THRESHOLD_PHASH: int = Field(default=8, ge=0, le=64)
    FORENSIC_MATCH_THRESHOLD_DHASH: int = Field(default=6, ge=0, le=64)
    FORENSIC_MATCH_THRESHOLD_AHASH: int = Field(default=6, ge=0, le=64)
    FORENSIC_MATCH_THRESHOLD_WHASH: int = Field(default=7, ge=0, le=64)
    # Global default for the search endpoint when per-hash isn't specified
    FORENSIC_DEFAULT_MAX_DISTANCE: int = Field(default=10, ge=0, le=64)
    # Auto-match threshold: a suspect image is considered a match if
    # any of the four hashes is within this distance of the ledger entry
    FORENSIC_AUTO_MATCH_DISTANCE: int = Field(default=10, ge=0, le=64)

    # ---- ZKP ----
    PEDERSEN_GROUP_BITS: int = 2048  # modulus bit-length

    # ---- Logging ----
    LOG_LEVEL: str = "INFO"
    LOG_JSON: bool = False

    # ---- CORS ----
    # Default permits everything for dev. In production set this to the
    # actual Wix origin(s) and the operator's own dashboard:
    #   CORS_ALLOW_ORIGINS=https://yoursite.wixsite.com/deep-trace,https://admin.yourdomain.com
    CORS_ALLOW_ORIGINS: Annotated[List[str], NoDecode] = Field(
        default_factory=lambda: ["*"],
        description="Allowed CORS origins (comma-separated in env). Use specific origins in production.",
    )

    @field_validator("API_KEYS", mode="before")
    @classmethod
    def _split_api_keys(cls, v):
        """Allow API_KEYS env var to be a comma-separated string."""
        if isinstance(v, str):
            return [k.strip() for k in v.split(",") if k.strip()]
        return v

    @field_validator("CORS_ALLOW_ORIGINS", mode="before")
    @classmethod
    def _split_cors(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v


@lru_cache
def get_settings() -> Settings:
    """Cached settings accessor."""
    return Settings()


# Module-level singleton for convenience
settings = get_settings()
