DOCKERFILE_PATH=./build/Dockerfile
BINARY_NAME=kubevuln

IMAGE?=quay.io/kubescape/$(BINARY_NAME)
TAG=v0.0.0

.PHONY: build test vet lint lint-all verify verify-image

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) cmd/http/main.go

test:
	go test ./...

vet:
	go vet ./...

lint:
	@base_ref=$${GITHUB_BASE_REF:-main}; \
	base=$$(git merge-base HEAD upstream/$$base_ref 2>/dev/null || git merge-base HEAD origin/$$base_ref 2>/dev/null || true); \
	if [ -n "$$base" ]; then \
		golangci-lint run --timeout=15m --new-from-rev="$$base"; \
	else \
		golangci-lint run --timeout=15m; \
	fi

lint-all:
	golangci-lint run --timeout=15m

verify: build test vet lint

verify-image: docker-build

docker-build:
	docker buildx build --platform linux/amd64 -t $(IMAGE):${TAG} -f $(DOCKERFILE_PATH) .
docker-push:
	docker push $(IMAGE):${TAG}
