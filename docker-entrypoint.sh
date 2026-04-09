#!/bin/bash
set -euo pipefail

WORKERS=${WORKERS:-1}
ACCESS_LOG=${ACCESS_LOG:--}
ERROR_LOG=${ERROR_LOG:--}
WORKER_TEMP_DIR=${WORKER_TEMP_DIR:-/dev/shm}
SKIP_DB_MIGRATION=${SKIP_DB_MIGRATION:-false}

# Initialize database
if [[ "$SKIP_DB_MIGRATION" == "true" ]]; then
    echo "Skipping DB migration"
else
    cd /opt/securevault && flask db upgrade
fi

# Start SecureVault
echo "Starting SecureVault"
exec gunicorn 'app:create_app()' \
    --bind '0.0.0.0:8000' \
    --workers $WORKERS \
    --worker-tmp-dir "$WORKER_TEMP_DIR" \
    --access-logfile "$ACCESS_LOG" \
    --error-logfile "$ERROR_LOG"
