.PHONY: help lint lint-check test test-verbose test-coverage clean install-dev install-build-system build-package install-package-uploader upload-package-test upload-package ci

help:
	@echo "Available targets:"
	@echo "  make lint              - Run linter with auto-fix and format code"
	@echo "  make lint-check        - Check linting and formatting without changes"
	@echo "  make test              - Run test suite"
	@echo "  make test-verbose      - Run test suite with verbose output"
	@echo "  make test-coverage     - Run test suite with coverage report"
	@echo "  make clean             - Clean build artifacts and cache"
	@echo "  make install-dev       - Install development dependencies"
	@echo "  make ci                - Run CI checks (lint-check + test-coverage)"
	@echo "  make build-package     - Build distribution package"
	@echo "  make upload-package-test - Upload to TestPyPI"
	@echo "  make upload-package    - Upload to PyPI"

lint:
	ruff check --fix; ruff format

lint-check:
	ruff check --no-fix && ruff format --check

test:
	python3 -m pytest test_2fa.py

test-verbose:
	python3 -m pytest test_2fa.py -v

test-coverage:
	python3 -m pytest test_2fa.py --cov=twofa --cov-report=term-missing --cov-report=html

clean:
	rm -rf build/ dist/ *.egg-info __pycache__ .pytest_cache .coverage htmlcov/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

install-dev:
	python3 -m pip install pytest pytest-cov ruff

install-build-system:
	python3 -m pip install --upgrade build

build-package:
	python3 -m build --sdist

install-package-uploader:
	python3 -m pip install --upgrade twine

upload-package-test:
	python3 -m twine upload --repository testpypi --verbose dist/*

upload-package:
	python3 -m twine upload --verbose dist/*

ci: lint-check test-coverage
	@echo "CI checks passed!"
