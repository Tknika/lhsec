FROM golang:1.25-bookworm AS tools

RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/owasp-amass/amass/v4/...@latest

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Python dependency manager
RUN pip install --no-cache-dir uv

# External scanning tools
COPY --from=tools /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=tools /go/bin/httpx /usr/local/bin/httpx
COPY --from=tools /go/bin/amass /usr/local/bin/amass

WORKDIR /app

# Install Python deps first for better layer caching
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev

# Application code
COPY . .

# Ensure data directories and entrypoint permissions
RUN mkdir -p /data/nuclei_results \
    && chmod +x /app/docker/entrypoint.sh

ENV PATH="/app/.venv/bin:/usr/local/bin:${PATH}"

EXPOSE 8000

CMD ["/app/docker/entrypoint.sh"]
