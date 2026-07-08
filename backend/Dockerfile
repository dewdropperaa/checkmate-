# Stage 1: Build Go security tools
FROM golang:1.22-alpine AS tools-builder

RUN apk add --no-cache git

ENV GOPATH=/go
ENV PATH="${GOPATH}/bin:${PATH}"

# Install ProjectDiscovery tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Stage 2: Python application
FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Go binaries from builder stage
COPY --from=tools-builder /go/bin/subfinder /opt/tools/subfinder
COPY --from=tools-builder /go/bin/httpx /opt/tools/httpx
COPY --from=tools-builder /go/bin/katana /opt/tools/katana

# Make tools executable and verify they work
RUN chmod +x /opt/tools/* && \
    /opt/tools/subfinder -version && \
    /opt/tools/httpx -version && \
    /opt/tools/katana -version

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Set tools directory in PATH
ENV PATH="/opt/tools:${PATH}" \
    TOOLS_BINARY_DIR="/opt/tools"

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
