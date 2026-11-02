FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 AUTO_CREATE_SCHEMA=false
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY templates ./templates
COPY static ./static
COPY migrations ./migrations
COPY configs ./configs
COPY alembic.ini ./
RUN pip install --no-cache-dir uv && uv sync --locked --no-dev --extra postgres && useradd --create-home --uid 10001 app && mkdir -p /data/objects /data/exports && chown -R app:app /app /data
USER app
ENV PATH="/app/.venv/bin:$PATH"
ENV DATABASE_URL=postgresql+psycopg://vulnkb:change-me@db:5432/vulnkb OBJECT_STORE_DIR=/data/objects EXPORT_DIR=/data/exports
EXPOSE 8000
CMD ["uvicorn", "vuln_kb.main:app", "--host", "0.0.0.0", "--port", "8000"]
