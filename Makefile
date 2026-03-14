.PHONY: install dev frontend qdrant ingest test lint clean docker-up docker-down docker-build docker-logs docker-monitoring setup run stop

# ── Quick Start ─────────────────────────────────────────────────────

# One-time setup: install deps, pull model, start Qdrant, ingest ATT&CK data
setup:
	cd backend && pip install -e ".[dev]"
	cd frontend && pnpm install
	ollama pull hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF
	docker compose up -d qdrant
	@echo "Waiting for Qdrant to be ready..."
	@sleep 3
	PYTHONPATH=. python -m backend.ingestion.ingest_attack
	@echo "\n✅ Setup complete! Run 'make run' to start the app."

# Start everything (Qdrant + Backend + Frontend)
run:
	docker compose up -d qdrant
	@echo "Starting backend and frontend..."
	@PYTHONPATH=. uvicorn backend.main:app --reload --port 8000 & \
	(cd frontend && pnpm dev) & \
	wait

# Stop background services
stop:
	@-pkill -f "uvicorn backend.main:app" 2>/dev/null || true
	@-pkill -f "vite" 2>/dev/null || true
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
