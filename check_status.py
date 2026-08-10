"""Quick status of what's installed and what isn't."""
import importlib
import subprocess
import sys

print("=" * 60)
print("DEEP-TRACE environment status")
print("=" * 60)
print(f"Python: {sys.version.split()[0]}")
print(f"Executable: {sys.executable}")
print()

# Key packages we care about
need = [
    ("fastapi", "fastapi"),
    ("uvicorn", "uvicorn"),
    ("sqlalchemy", "sqlalchemy"),
    ("asyncpg", "asyncpg"),
    ("aiosqlite", "aiosqlite"),
    ("psycopg2", "psycopg2"),
    ("alembic", "alembic"),
    ("c2pa", "c2pa"),
    ("imagehash", "imagehash"),
    ("reedsolo", "reedsolo"),
    ("structlog", "structlog"),
    ("opencv", "cv2"),
    ("numpy", "numpy"),
    ("Pillow", "PIL"),
    ("pydantic", "pydantic"),
    ("pydantic_settings", "pydantic_settings"),
    ("httpx", "httpx"),
    ("pytest", "pytest"),
    ("pytest_asyncio", "pytest_asyncio"),
    ("python_multipart", "multipart"),
    ("starlette", "starlette"),
]

ok = []
miss = []
for label, modname in need:
    try:
        m = importlib.import_module(modname)
        v = getattr(m, "__version__", "?")
        ok.append((label, v))
    except Exception as e:
        miss.append((label, type(e).__name__))

print(f"OK ({len(ok)}):")
for label, v in sorted(ok):
    print(f"  [OK]   {label:<22} {v}")

if miss:
    print()
    print(f"MISSING ({len(miss)}):")
    for label, err in sorted(miss):
        print(f"  [--]   {label:<22} {err}")

# Check docker
print()
print("Container runtimes:")
for cmd in ("docker", "podman", "nerdctl"):
    try:
        out = subprocess.run([cmd, "--version"], capture_output=True, text=True, timeout=3)
        if out.returncode == 0:
            print(f"  [OK]   {cmd}: {out.stdout.strip() or out.stderr.strip()}")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print(f"  [--]   {cmd}: not available")

print()
print(f"Total: {len(ok)} installed, {len(miss)} missing")
