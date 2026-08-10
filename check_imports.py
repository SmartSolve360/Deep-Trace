"""Check which optional deps are present."""
mods = ["imagehash", "pywt", "scipy", "fastapi", "uvicorn", "sqlalchemy",
        "asyncpg", "aiosqlite", "reedsolo", "structlog", "pydantic_settings",
        "PIL", "cv2", "numpy", "pydantic", "httpx"]
for m in mods:
    try:
        __import__(m)
        print(f"OK    {m}")
    except Exception as e:
        print(f"MISS  {m}: {type(e).__name__}")
