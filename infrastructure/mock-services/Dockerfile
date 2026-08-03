# Disposable local mock services (idp / graph / ai). Never for production.
FROM python:3.13-slim

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY mock_idp.py mock_graph.py mock_ai.py ./

ENV PYTHONUNBUFFERED=1
EXPOSE 8443 8181 8282

CMD ["python", "-m", "uvicorn", "mock_idp:app", "--host", "0.0.0.0", "--port", "8443"]
