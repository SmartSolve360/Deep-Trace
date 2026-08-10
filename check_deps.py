"""One-shot dep checker."""
import importlib
import sys

need = [
    "fastapi", "uvicorn", "sqlalchemy", "asyncpg", "imagehash",
    "reedsolo", "structlog", "aiosqlite", "pytest", "pydantic_settings",
    "python_multipart", "alembic", "c2pa", "psycopg2",
    "PIL", "cv2", "numpy", "pydantic", "httpx",
]

ok = 0
miss = 0
for name in need:
    try:
        m = importlib.import_module(name)
        v = getattr(m, "__version__", "?")
        print(f"OK     {name:<22} {v}")
        ok += 1
    except Exception as e:
        print(f"MISS   {name:<22} {type(e).__name__}: {e}")
        miss += 1

print(f"\n{ok} ok, {miss} missing")
sys.exit(0 if miss == 0 else 2)
