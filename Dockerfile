ARG BASE_IMAGE
FROM ${BASE_IMAGE}
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_NO_CACHE=1
COPY pyproject.toml uv.lock ./
RUN python -m pip install --no-cache-dir uv==0.9.11 \
    && uv sync --frozen --no-dev --no-install-project
COPY lab ./lab
COPY fixtures ./fixtures
COPY cases ./cases
USER 10001:10001
ENTRYPOINT ["/app/.venv/bin/python", "-m", "lab.isolated_component"]
