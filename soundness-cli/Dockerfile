# Build stage
FROM rust:latest as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    git \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app
COPY . .

RUN cargo build --release

# Runtime stage
FROM rust:latest

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user and data directory
RUN useradd -m soundness && \
    mkdir -p /home/soundness/.soundness && \
    chown -R soundness:soundness /home/soundness/.soundness

WORKDIR /usr/local/bin

# Copy the built binary from builder
COPY --from=builder /usr/src/app/target/release/soundness-cli .
RUN chown soundness:soundness /usr/local/bin/soundness-cli

# Switch to non-root user
USER soundness

# Set the entrypoint
ENTRYPOINT ["soundness-cli"] 