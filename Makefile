.PHONY: help install lint format test test-unit test-integration test-model \
        run api dashboard mock train pipeline clean deploy

# ─── Help ──────────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "  SAP Threat Detector — Available Commands"
	@echo "  ----------------------------------------"
	@echo "  make install           Install runtime dependencies"
	@echo "  make lint              Run ruff check"
	@echo "  make format            Run ruff format"
	@echo "  make test              Run unit + integration tests"
	@echo "  make test-unit         Run unit tests only"
	@echo "  make test-integration  Run integration tests only"
	@echo "  make test-model        Run model quality tests"
	@echo "  make mock              Generate mock SAP logs"
	@echo "  make train             Train a new model from mock/real data"
	@echo "  make run               Run the full pipeline locally (no FastAPI)"
	@echo "  make api               Run FastAPI with auto-reload"
	@echo "  make dashboard         Launch the Streamlit dashboard"
	@echo "  make pipeline          Alias for 'make run'"
	@echo "  make clean             Remove build / cache artifacts"
	@echo "  make deploy            cf push to SAP BTP Cloud Foundry"
	@echo ""

# ─── Environment ───────────────────────────────────────────────────────────

install:
	pip install -r requirements.txt

lint:
	ruff check src/ tests/ scripts/

format:
	ruff format src/ tests/ scripts/

# ─── Testing ───────────────────────────────────────────────────────────────

test: test-unit test-integration

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

test-model:
	pytest tests/model/ -v

# ─── Runtime ───────────────────────────────────────────────────────────────

mock:
	python3 -m scripts.generate_mock_logs --rows 5000 --attack-ratio 0.05 \
	    --with-spikes --with-brute-force

train:
	python3 -m scripts.train_model

run:
	python3 -m scripts.run_pipeline_local

pipeline: run

api:
	uvicorn src.api.main:app --reload

dashboard:
	streamlit run src/dashboard/app.py

# ─── Housekeeping ──────────────────────────────────────────────────────────

clean:
	find . -type d -name '__pycache__' -prune -exec rm -rf {} +
	find . -type d -name '.pytest_cache' -prune -exec rm -rf {} +
	find . -type d -name '.ruff_cache' -prune -exec rm -rf {} +
	find . -type d -name '.mypy_cache' -prune -exec rm -rf {} +
	rm -rf build dist *.egg-info

deploy:
	cf push -f infra/manifest.yml
