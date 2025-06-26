FROM debian:bookworm-slim

# Install tar and any other dependencies
RUN apt-get update && apt-get install -y tar curl && rm -rf /var/lib/apt/lists/*

# Create nonroot user and group
RUN groupadd -r -g 65532 nonroot && \
    useradd -r -s /bin/false -u 65532 -g nonroot nonroot

USER root
WORKDIR /home/nonroot/

# Copy the pre-built binary from host
COPY kubevuln /usr/bin/kubevuln

# Copy dive and trufflehog binaries (they should already be executable)
COPY dive /usr/bin/dive
COPY trufflehog /usr/bin/trufflehog

ARG image_version
ENV RELEASE=$image_version

ENTRYPOINT ["/usr/bin/kubevuln"]
