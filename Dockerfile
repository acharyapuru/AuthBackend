# Use the official Python image from the Docker Hub
FROM python:3.12-slim AS development_build 

# Argument and environment variables
ARG DJANGO_ENV

ENV DJANGO_ENV=${DJANGO_ENV} \
    PYTHONFAULTHANDLER=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_VERSION=1.8.2 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_CACHE_DIR='/var/cache/pypoetry'

# Install system dependencies and Poetry
RUN apt-get update && apt-get install --no-install-recommends -y \
    bash \
    build-essential \
    curl \
    gettext \
    git \
    libpq-dev \
    wget \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/* \
    && pip install "poetry==$POETRY_VERSION" \
    && poetry --version

# Set working directory
WORKDIR /code

# Copy dependency files
COPY pyproject.toml poetry.lock /code/

# Install Python dependencies
RUN poetry install

# Copy the rest of the application code
COPY src/ /code/

# Expose port 8000
EXPOSE 8000

# Start the Django server (optional)
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]