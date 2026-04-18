#!/bin/bash
# Deploy Arniko Security Platform
# Standalone deploy — runs from the repo root.

set -e

echo "Deploying Arniko..."

pnpm install
pnpm build
pnpm test

PORT="${PORT:-3010}"
echo "Starting server on port ${PORT}..."

if command -v pm2 &> /dev/null; then
    PORT="${PORT}" pm2 start dist/server.js --name arniko-security --update-env
    pm2 save
else
    echo "pm2 not found. Run: node dist/server.js"
    exit 1
fi

echo "Dashboard: http://localhost:${PORT}/api/dashboard/summary"
echo "Health:    http://localhost:${PORT}/health"
