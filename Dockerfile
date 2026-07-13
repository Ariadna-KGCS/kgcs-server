# KGCS Orchestrator API — container image
#
# Usage (local build):
#   docker build -t kgcs-orchestrator .
#   docker run -p 8080:8080 --env-file .env kgcs-orchestrator
#
# Environment variables:
#   See .env.example for the full list of supported variables.

FROM python:3.12-slim

WORKDIR /app

# Install dependencies in a separate layer so they are cached between builds.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source.  Only the packages consumed by the API are needed.
COPY agents/     agents/
COPY orchestrator/ orchestrator/
COPY ai/         ai/
COPY docs/04-graph/schemas/ docs/04-graph/schemas/

# Ensure the working directory is on the Python path.
ENV PYTHONPATH=/app

# Port exposed by aiohttp (overridable at runtime with -e PORT=...).
ENV PORT=8080
EXPOSE 8080

# Run the API server.
CMD ["python", "-m", "orchestrator.api"]
