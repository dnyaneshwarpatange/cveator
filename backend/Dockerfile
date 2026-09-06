FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock

COPY app ./app
COPY alembic.ini ./
COPY alembic ./alembic

RUN groupadd --system app && useradd --system --gid app --home-dir /app app \
    && chown -R app:app /app
USER app

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
