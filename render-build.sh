#!/usr/bin/env bash
# Render build script. Runs before the start command.
# Render automatically provides DATABASE_URL via the linked Postgres service.

set -euo pipefail

echo "==> Python version:"
python --version

echo "==> Upgrading pip + installing requirements:"
pip install --upgrade pip wheel
pip install --no-cache-dir -r requirements.txt

echo "==> Running migrations:"
alembic upgrade head

echo "==> Build complete."
