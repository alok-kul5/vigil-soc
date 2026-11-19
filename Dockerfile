FROM python:3.11-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY triage_agent ./triage_agent
COPY examples ./examples
COPY eval ./eval
ENV PYTHONUNBUFFERED=1 TRIAGE_RUNS_DIR=/data/runs
VOLUME /data
EXPOSE 8000
RUN useradd --create-home app && mkdir -p /data && chown app /data
USER app
HEALTHCHECK --interval=15s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"
CMD ["uvicorn", "triage_agent.web.app:app", "--host", "0.0.0.0", "--port", "8000"]
