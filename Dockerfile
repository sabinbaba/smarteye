# ===============================
# Builder stage
# ===============================
FROM python:3.9-slim AS builder

ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL org.opencontainers.image.created=$BUILD_DATE \
      org.opencontainers.image.title="hybrid-ids" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$VCS_REF

# Build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libpcap-dev \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt requirements_enhanced.txt ./

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r requirements_enhanced.txt

# ===============================
# Production stage
# ===============================
FROM python:3.9-slim AS production

# Runtime dependencies + capabilities tool
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libssl3 \
    libffi8 \
    iproute2 \
    tcpdump \
    curl \
    netcat-openbsd \
    sqlite3 \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash appuser

WORKDIR /app

# Copy Python environment
COPY --from=builder /usr/local /usr/local

# Copy app code
COPY . .

# App directories
RUN mkdir -p logs data model && \
    chmod +x main.py && \
    chown -R appuser:appuser /app

# Grant packet capture without root
RUN setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3)) && \
    setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which tcpdump))

USER appuser

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV FLASK_APP=main.py
ENV FLASK_ENV=production
ENV PORT=8090

EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl -f http://localhost:8090/api/network-status || exit 1

ENTRYPOINT ["python", "main.py"]

# ===============================
# Development stage
# ===============================
FROM production AS development

ENV FLASK_ENV=development
ENV FLASK_DEBUG=1

USER root
RUN apt-get update && apt-get install -y \
    git nano vim htop \
    && rm -rf /var/lib/apt/lists/*

USER appuser
CMD ["tail", "-f", "/dev/null"]
