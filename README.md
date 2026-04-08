# Module 10 - Secure User Model, Testing, and CI/CD

This project extends a FastAPI application by adding a secure user model with SQLAlchemy, Pydantic validation, password hashing, automated testing, and a CI/CD pipeline with GitHub Actions and Docker Hub.

## Features

- FastAPI application
- SQLAlchemy user model
- Pydantic schema validation
- Password hashing and verification
- Unit, integration, and end-to-end tests
- GitHub Actions CI/CD workflow
- Docker image pushed to Docker Hub

## Project Structure

- `app/models/` - SQLAlchemy models
- `app/schemas/` - Pydantic schemas
- `tests/unit/` - unit tests
- `tests/integration/` - integration tests
- `tests/e2e/` - end-to-end tests
- `.github/workflows/` - GitHub Actions workflow
- `Dockerfile` - container setup

## How to Run Locally

### 1. Create and activate a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate

## Install dependencies
- pip install --upgrade pip
- pip install -r requirements.txt
- playwright install

## Start PostgreSQL with Docker
- docker compose up -d db

##Initialize database
- python -m app.database_init

##Run tests
- pytest tests/unit
- pytest tests/integration/
- pytest tests/e2e