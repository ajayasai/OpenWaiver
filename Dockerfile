FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --no-cache-dir . && useradd --create-home --uid 10001 openwaiver \
    && mkdir /data && chown openwaiver:openwaiver /data
USER openwaiver
EXPOSE 8765
ENTRYPOINT ["openwaiver", "--db", "/data/openwaiver.sqlite3", "serve"]
CMD ["--auth-file", "/run/secrets/openwaiver-auth.json", "--host", "0.0.0.0", "--port", "8765", "--allow-remote"]
