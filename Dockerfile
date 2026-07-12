FROM python:3.11-slim

WORKDIR /app

# Install system deps for spaCy and matplotlib
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN python -m spacy download en_core_web_sm

COPY src/ ./src/

# Set PYTHONPATH so src/ modules resolve correctly
ENV PYTHONPATH=/app/src

CMD ["python", "src/orchestrator.py"]
