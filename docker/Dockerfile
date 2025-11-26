FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install the package in editable mode
RUN pip install -e .

# Create non-root user
RUN useradd -m loghunter && chown -R loghunter:loghunter /app
USER loghunter

CMD ["uvicorn", "src.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
