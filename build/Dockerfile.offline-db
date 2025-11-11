# Stage 1: The builder stage
FROM alpine AS builder

# Install curl to download the files
RUN apk add --no-cache curl jq

# Set the working directory
WORKDIR /app/grype-db

# Download the listing.json file
ARG GRYPE_DB_ROOT=https://grype.anchore.io/databases/v6
RUN curl -O $GRYPE_DB_ROOT/latest.json

# Extract the database URL from the listing file and download it
RUN DB_PATH=$(jq -r '.path' latest.json) && \
    curl -O ${GRYPE_DB_ROOT}/$DB_PATH

# Stage 2: The final production image
FROM nginxinc/nginx-unprivileged:alpine

# Copy the generated artifacts from the builder stage
COPY --from=builder /app/grype-db/ /usr/share/nginx/html/databases/v6/

# Command to run NGINX
CMD ["nginx", "-g", "daemon off;"]
