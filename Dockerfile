FROM python:3.11-slim AS base

WORKDIR /app


# Build stage: build the application wheel
FROM base AS builder

COPY pyproject.toml README.md ./
COPY strixsec/ ./strixsec/

RUN pip install --upgrade pip && \
    pip wheel --no-cache-dir --wheel-dir /wheels .


# Runtime stage: minimal image with runtime dependencies only
FROM python:3.11-slim AS runtime

# Create non-root user
RUN groupadd --gid 1001 strixsec && \
    useradd --uid 1001 --gid 1001 --create-home --shell /usr/sbin/nologin strixsec

WORKDIR /app

# Install application wheel
COPY --from=builder --chown=strixsec:strixsec /wheels /wheels

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir --no-index --find-links /wheels strixsec && \
    rm -rf /wheels


# Runtime data lives outside /app
ENV STRIXSEC_HOME=/data

WORKDIR /data

USER strixsec

# CLI is the only intended use case
ENTRYPOINT ["strixsec"]
CMD ["--help"]