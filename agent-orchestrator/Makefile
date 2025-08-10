# Development commands for agent-orchestrator

.PHONY: help install format lint type-check test clean dev-install

help:  ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install production dependencies
	uv sync

dev-install:  ## Install all dependencies including dev tools
	uv sync --group dev

format:  ## Format code with Black
	uv run black .

format-check:  ## Check if code is formatted correctly
	uv run black --check .

lint:  ## Run linting with Ruff
	uv run ruff check .

lint-fix:  ## Run linting with Ruff and fix auto-fixable issues
	uv run ruff check . --fix

type-check:  ## Run type checking with MyPy
	uv run mypy .

quality:  ## Run all quality checks (format-check, lint, type-check)
	make format-check
	make lint
	make type-check

quality-fix:  ## Run format and lint-fix
	make format
	make lint-fix

pre-commit-install:  ## Install pre-commit hooks
	uv run pre-commit install

pre-commit-run:  ## Run pre-commit on all files
	uv run pre-commit run --all-files

clean:  ## Clean cache files
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +
