.PHONY: install dev frontend qdrant ingest test lint clean docker-up docker-down docker-build docker-logs docker-monitoring setup run stop version version-bump-patch version-bump-minor version-bump-major

VERSION := $(shell cat VERSION)

# ── Quick Start ─────────────────────────────────────────────────────

# One-time setup: install deps, pull model, start Qdrant, ingest ATT&CK data
setup:
	cd backend && pip install -e ".[dev]"
	cd frontend && pnpm install
	@echo "Ensuring Ollama is running..."
	@if ! curl -sf http://localhost:11434 > /dev/null 2>&1; then \
		ollama serve & \
		sleep 2; \
	fi
	ollama pull hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF
	docker compose up -d qdrant
	@echo "Waiting for Qdrant to be ready..."
	@sleep 3
	PYTHONPATH=. python -m backend.ingestion.ingest_attack
	@echo "\n✅ Setup complete! Run 'make run' to start the app."

# Start everything (Qdrant + Backend + Frontend) — single command, colored output
run:
	@if lsof -ti:8000 > /dev/null 2>&1; then \
		echo "⚠️  Port 8000 is in use. Run 'make stop' first."; \
		exit 1; \
	fi
	@echo "Starting all services (v$(VERSION))..."
	honcho start -f Procfile.dev

# Stop background services
stop:
	@-pkill -f "uvicorn backend.main:app" 2>/dev/null || true
	@-pkill -f "vite" 2>/dev/null || true
	@-lsof -ti:8000 | xargs kill -9 2>/dev/null || true
	docker compose down
	@echo "All services stopped."

# ── Development ──────────────────────────────────────────────────────

# Install all backend dependencies
install:
	cd backend && pip install -e ".[dev]"

# Start FastAPI backend with hot-reload
dev:
	PYTHONPATH=. uvicorn backend.main:app --reload --port 8000

# Start React frontend dev server
frontend:
	cd frontend && pnpm dev

# Start Qdrant via Docker
qdrant:
	docker compose up -d qdrant

# Ingest MITRE ATT&CK data into Qdrant
ingest:
	python -m backend.ingestion.ingest_attack

# Pull the Foundation-Sec model
pull-model:
	ollama pull hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF

# ── Versioning ─────────────────────────────────────────────────────────

# Show current version
version:
	@echo $(VERSION)

# Bump patch version (0.1.0 → 0.1.1)
version-bump-patch:
	@python3 scripts/bump_version.py patch

# Bump minor version (0.1.0 → 0.2.0)
version-bump-minor:
	@python3 scripts/bump_version.py minor

# Bump major version (0.1.0 → 1.0.0)
version-bump-major:
	@python3 scripts/bump_version.py major

# ── Testing ──────────────────────────────────────────────────────────

# Run backend tests
test:
	PYTHONPATH=. pytest backend/tests/ -v

# ── Code Quality ─────────────────────────────────────────────────────

# Lint
lint:
	cd backend && ruff check . && ruff format --check .

# ── Docker (Full Deployment) ─────────────────────────────────────────

# Build and start all services (Qdrant + Backend + Frontend)
docker-up:
	docker compose up -d --build

# Stop all services
docker-down:
	docker compose down

# Build Docker images without starting
docker-build:
	docker compose build

# Tail logs from all services
docker-logs:
	docker compose logs -f

# Ingest data inside Docker backend container
docker-ingest:
	docker compose exec backend python -m backend.ingestion.ingest_attack

# Start with Prometheus monitoring
docker-monitoring:
	docker compose --profile monitoring up -d --build

# ── Cleanup ──────────────────────────────────────────────────────────

# Clean generated files
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	rm -rf backend/*.egg-info
