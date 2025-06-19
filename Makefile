DOCKERFILE_PATH=./build/Dockerfile
BINARY_NAME=kubevuln

IMAGE?=quay.io/kubescape/$(BINARY_NAME)
TAG=v0.0.0

# Binary versions
DIVE_VERSION ?= 0.12.0
TRUFFLEHOG_VERSION ?= 3.89.2

# Download URLs
DIVE_URL = https://github.com/wagoodman/dive/releases/download/v$(DIVE_VERSION)/dive_$(DIVE_VERSION)_linux_amd64.tar.gz
TRUFFLEHOG_URL = https://github.com/trufflesecurity/trufflehog/releases/download/v$(TRUFFLEHOG_VERSION)/trufflehog_$(TRUFFLEHOG_VERSION)_linux_amd64.tar.gz

# Download dive binary if not present
dive:
	@if [ ! -f ./dive ]; then \
		echo "Downloading dive v$(DIVE_VERSION)..."; \
		curl -sSL $(DIVE_URL) | tar xz -C . dive; \
		chmod +x ./dive; \
		echo "✅ Dive binary downloaded successfully"; \
	else \
		echo "✅ Dive binary already exists"; \
	fi

# Download trufflehog binary if not present
trufflehog:
	@if [ ! -f ./trufflehog ]; then \
		echo "Downloading trufflehog v$(TRUFFLEHOG_VERSION)..."; \
		curl -sSL $(TRUFFLEHOG_URL) | tar xz -C . trufflehog; \
		chmod +x ./trufflehog; \
		echo "✅ TruffleHog binary downloaded successfully"; \
	else \
		echo "✅ TruffleHog binary already exists"; \
	fi

# Build the main binary with dependencies
build: dive trufflehog
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) cmd/http/main.go

# Build CLI binary with dependencies
build-cli: dive trufflehog
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME)-cli cmd/cli/main.go

# Build both binaries
all: build build-cli

docker-build: dive trufflehog
	docker buildx build --platform linux/amd64 -t $(IMAGE):${TAG} -f $(DOCKERFILE_PATH) .

docker-push:
	docker push $(IMAGE):${TAG}

# Clean up binaries
clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)-cli dive trufflehog
	rm -rf dive-results trufflehog-results

# Show help
help:
	@echo "Available targets:"
	@echo "  build      - Build main kubevuln binary with dive and trufflehog"
	@echo "  build-cli  - Build CLI binary with dive and trufflehog"
	@echo "  all        - Build both binaries"
	@echo "  dive       - Download dive binary only"
	@echo "  trufflehog - Download trufflehog binary only"
	@echo "  clean      - Remove all binaries and results"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-push  - Push Docker image"
