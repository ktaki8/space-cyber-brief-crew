# Dashboard, API and auditor in one image.
#   docker build -t space-cyber-brief-crew .
#   docker run --rm -p 8000:8000 --env-file .env space-cyber-brief-crew
# Then open http://localhost:8000/dashboard
# Auditing needs no key. Live crew runs need a model key (or MODEL=ollama/...)
# and CREW_ACCESS_KEY in .env.
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN pip install --no-cache-dir -e . && useradd -m app && mkdir -p output && chown -R app /app/output
USER app
EXPOSE 8000
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
