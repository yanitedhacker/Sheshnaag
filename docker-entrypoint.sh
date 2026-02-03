#!/bin/bash
set -e

echo "Starting CVE Threat Radar..."

# Run database migrations if alembic is configured
if [ -f "alembic.ini" ]; then
    echo "Running database migrations..."
    alembic upgrade head || echo "Migration failed or not needed, continuing..."
fi

# Start the application
echo "Starting uvicorn server..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
