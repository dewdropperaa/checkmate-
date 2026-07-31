# Stage 1: Build Go security tools
FROM golang:1.26-alpine AS tools-builder

RUN apk add --no-cache git

ENV GOPATH=/go
ENV PATH="${GOPATH}/bin:${PATH}"
# Fallback mirrors help on VPS builds when proxy.golang.org times out.
ENV GOPROXY=https://proxy.golang.org,https://goproxy.io,direct

# Install separately so successful tools stay cached if a later download fails.
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Stage 2: Node tools (retire.js)
FROM node:20-alpine AS node-builder

RUN npm install -g retire@latest

# Stage 3: Python application
FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
  && rm -rf /var/lib/apt/lists/*

# Copy Go binaries from builder stage
COPY --from=tools-builder /go/bin/subfinder /opt/tools/subfinder
COPY --from=tools-builder /go/bin/httpx /opt/tools/httpx
COPY --from=tools-builder /go/bin/katana /opt/tools/katana
COPY --from=tools-builder /go/bin/nuclei /opt/tools/nuclei

# Copy retire.js from node stage
COPY --from=node-builder /usr/local/bin/retire /opt/tools/retire

# Install testssl.sh and sqlmap
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && \
    ln -s /opt/testssl/testssl.sh /opt/tools/testssl.sh && \
  pip install --no-cache-dir sqlmap

# Pre-fetch nuclei templates so first scan is not empty
RUN /opt/tools/nuclei -update-templates -silent || true

# Make tools executable and verify core binaries
RUN chmod +x /opt/tools/* /opt/testssl/testssl.sh && \
    /opt/tools/subfinder -version && \
    /opt/tools/httpx -version && \
    /opt/tools/katana -version && \
    /opt/tools/nuclei -version

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Set tools directory in PATH
ENV PATH="/opt/tools:${PATH}" \
    TOOLS_BINARY_DIR="/opt/tools"

EXPOSE 8000

COPY scripts/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
