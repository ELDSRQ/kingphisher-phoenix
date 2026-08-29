# Disposable local mock services (idp / graph / ai). Never for production.
FROM ghcr.io/astral-sh/uv:0.11.28@sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa AS uvbin
FROM cgr.dev/chainguard/python@sha256:aa8fd2447b8b52922db57deb3894b622c3229387aaaec5934d64b85dbff6eb17 AS builder
COPY --from=uvbin /uv /uvx /usr/local/bin/
WORKDIR /srv
COPY --chown=65532:65532 requirements.txt ./
RUN UV_PYTHON_DOWNLOADS=never uv venv /srv/.venv \
    && UV_PYTHON_DOWNLOADS=never uv pip install \
        --python /srv/.venv/bin/python \
        --only-binary=:all: \
        --require-hashes \
        --requirement requirements.txt

FROM cgr.dev/chainguard/python@sha256:ee37f5e4fb445732409626797dccb6f2a6337872def2bab48729ee61b335fa77
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
