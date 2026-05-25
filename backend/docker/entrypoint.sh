#!/usr/bin/env sh
set -eu

mkdir -p /data/nuclei_results /root/nuclei-templates

if [ "${NUCLEI_UPDATE_TEMPLATES:-true}" = "true" ]; then
  echo "[entrypoint] Updating nuclei templates..."
  nuclei -update-templates || echo "[entrypoint] nuclei template update failed; continuing with existing templates"
fi

exec uv run uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
