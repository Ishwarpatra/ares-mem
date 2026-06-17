FROM python:3.11-slim

LABEL maintainer="Project ARES-Mem"
LABEL description="Production-grade multi-agent cybersecurity defense system"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Attempt to download spaCy model (non-fatal if it fails)
RUN python -m spacy download en_core_web_sm || \
    echo "[WARN] spaCy model not downloaded. Falling back to blank tokenizer."

# Download NLTK punkt tokenizer for perplexity scoring
RUN python -c "import nltk; nltk.download('punkt', quiet=True); nltk.download('punkt_tab', quiet=True)" || \
    echo "[WARN] NLTK punkt not downloaded."

# Copy project source and tests
COPY src/ ./src/
COPY tests/ ./tests/

ENV PYTHONPATH=/app/src

CMD ["python", "src/main.py"]
