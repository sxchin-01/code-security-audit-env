FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
		PYTHONUNBUFFERED=1 \
		PIP_NO_CACHE_DIR=1 \
		PIP_DISABLE_PIP_VERSION_CHECK=1 \
		PORT=7860

WORKDIR /app

RUN useradd --create-home --shell /bin/bash appuser

COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r /app/requirements.txt

COPY . /app

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
	CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % __import__('os').environ.get('PORT','7860'))"

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-7860}"]
