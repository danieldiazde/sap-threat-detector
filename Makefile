.PHONY: install lint test run dashboard deploy help

# Default target
help:
	@echo ""
	@echo "  SAP Threat Detector — Available Commands"
	@echo "  ----------------------------------------"
	@echo "  make install     Install all dependencies"
	@echo "  make lint        Run code linter (ruff)"
	@echo "  make test        Run all tests"
	@echo "  make run         Run the full detection pipeline (uses mock data if no API key)"
	@echo "  make dashboard   Launch the Streamlit dashboard locally"
	@echo "  make deploy      Deploy to SAP BTP Cloud Foundry"
	@echo "  make mock        Generate mock SAP log data for development"
	@echo ""

install:
	pip install -r requirements.txt

lint:
	ruff check src/ tests/

test:
	pytest tests/unit/ tests/integration/ -v

test-model:
	pytest tests/model/ -v

run:
	python -m src.ingestion.sap_log_fetcher

dashboard:
	streamlit run src/dashboard/app.py

mock:
	python scripts/generate_mock_logs.py

deploy:
	cf push -f infra/manifest.yml
