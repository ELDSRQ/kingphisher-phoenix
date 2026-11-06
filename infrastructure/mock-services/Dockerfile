# Disposable local mock services (idp / graph / ai). Never for production.
FROM ghcr.io/astral-sh/uv:0.11.28@sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa AS uvbin
FROM cgr.dev/chainguard/python@sha256:fe4dbb574f811d271ac002a3e0270659f69841738276ef2d0084323baf1d75df AS builder
COPY --from=uvbin /uv /uvx /usr/local/bin/
WORKDIR /srv
COPY --chown=65532:65532 requirements.txt ./
RUN UV_PYTHON_DOWNLOADS=never uv venv /srv/.venv \
    && UV_PYTHON_DOWNLOADS=never uv pip install \
        --python /srv/.venv/bin/python \
        --only-binary=:all: \
        --require-hashes \
        --requirement requirements.txt

FROM cgr.dev/chainguard/python@sha256:f3e5face39b0acd813fae456df27b33bf6a6bffba5d201d15f6498138cb8fd96
WORKDIR /srv
COPY --from=builder --chown=65532:65532 /srv/.venv /srv/.venv
COPY --chown=65532:65532 mock_idp.py mock_graph.py mock_ai.py ./
ENV PATH="/srv/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
USER 65532:65532
EXPOSE 8443 8181 8282

STOPSIGNAL SIGTERM
ENTRYPOINT []
CMD ["python", "-m", "uvicorn", "mock_idp:app", "--host", "0.0.0.0", "--port", "8443"]
