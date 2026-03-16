#!/usr/bin/env bash
# Start Ollama if it's not already running.
set -e

if curl -sf http://localhost:11434 > /dev/null 2>&1; then
  echo "Ollama is already running."
  # Keep the process alive so honcho doesn't exit
  tail -f /dev/null
else
  echo "Starting Ollama..."
  exec ollama serve
fi
