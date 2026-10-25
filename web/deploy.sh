#!/usr/bin/env bash
# Deploy the web version of SindriCAD from this repo to the server folders.
# Run as the developer, from anywhere:   web/deploy.sh
#   BUILD=0 web/deploy.sh    skip `npm run build` (reuse the existing dist/)
#
# Layout it produces:
#   /var/www/sindricad     only what runs: dist/, web/gateway.py, sidecar sources  (back this up)
#   /opt/sindricad         Python environments for sidecar and gateway            (rebuildable)
#   /var/lib/sindri-web    students' temporary session folders (owned by the service user)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
APP="${SINDRI_APP:-/var/data/www/cad.jajtnerovi.cz}"
VENVS="${SINDRI_VENVS:-/opt/sindricad}"
BUILD="${BUILD:-1}"

# Sidecar: Python <3.13 downloaded by uv to $VENVS/python (never $HOME: ProtectHome=yes).
# Gateway: system Python (security updates via apt).
export UV_PYTHON_INSTALL_DIR="$VENVS/python"
SIDECAR_PYTHON="${SIDECAR_PYTHON:-3.12}"

cd "$REPO"
if [ "$BUILD" = 1 ]; then
  echo "== building frontend"
  VITE_SINDRI_WS=/__sindri/ws npm run build
fi
[ -f dist/index.html ] || { echo "dist/index.html missing - build first"; exit 1; }

echo "== copying runtime files to $APP"
mkdir -p "$APP/web" "$VENVS"
rsync -a --delete dist/ "$APP/dist/"
rsync -a --delete \
  --exclude '.venv/' --exclude '__pycache__/' --exclude '.pytest_cache/' \
  --exclude 'test_*.py' --exclude 'tests/' --exclude '*.log' \
  sidecar/ "$APP/sidecar/"
rsync -a web/gateway.py web/pyproject.toml web/uv.lock "$APP/web/"

echo "== sidecar environment ($VENVS/sidecar-venv)"
(cd "$APP/sidecar" && UV_PROJECT_ENVIRONMENT="$VENVS/sidecar-venv" uv sync --no-dev --managed-python --python "$SIDECAR_PYTHON")
if ! grep -qw sse4_2 /proc/cpuinfo; then
  echo "   CPU without SSE4.2: pinning numpy<2.4"
  uv pip install --python "$VENVS/sidecar-venv/bin/python" "numpy<2.4"
fi
"$VENVS/sidecar-venv/bin/python" -c \
  "import numpy, OCP; print('   sidecar imports OK, numpy', numpy.__version__)"

echo "== gateway environment ($VENVS/web-venv)"
(cd "$APP/web" && UV_PROJECT_ENVIRONMENT="$VENVS/web-venv" uv sync --no-managed-python)

if systemctl cat sindri-web >/dev/null 2>&1; then
  echo "== restarting sindri-web"
  sudo systemctl restart sindri-web
  sleep 2
  systemctl --no-pager --lines=5 status sindri-web || true
else
  echo "== service sindri-web not installed yet - done"
fi
