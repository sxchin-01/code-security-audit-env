FROM python:3.11-slim

# Create non-root user (HF requirement best practice)
RUN useradd -m -u 1000 user
USER user

WORKDIR /app

# Copy requirements first (better caching)
COPY --chown=user requirements.txt requirements.txt

# Install dependencies
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# Copy rest of the app
COPY --chown=user . .

# Expose correct port
EXPOSE 7860

# Start FastAPI
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860"]