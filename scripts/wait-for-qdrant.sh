#!/usr/bin/env bash
# Wait for Qdrant to be ready before starting the backend.
set -e

echo "Waiting for Qdrant on localhost:6333..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:6333 > /dev/null 2>&1; then
    echo "✅ Qdrant is ready."
    exit 0
  fi
  sleep 1
done

echo "❌ Qdrant failed to start within 30s"
exit 1
