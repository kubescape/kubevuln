DOCKERFILE_PATH=./build/Dockerfile
BINARY_NAME=kubevuln

IMAGE?=quay.io/kubescape/$(BINARY_NAME)
TAG=v0.0.0

.PHONY: build test vet lint verify verify-image

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) cmd/http/main.go

test:
	go test ./...

vet:
	go vet ./...

lint:
	@base=$$(git merge-base HEAD upstream/main 2>/dev/null || git merge-base HEAD origin/main 2>/dev/null || true); \
	if [ -n "$$base" ]; then \
		golangci-lint run --new-from-rev "$$base"; \
	else \
		golangci-lint run; \
	fi

verify: build test vet lint

verify-image: docker-build

docker-build:
	docker buildx build --platform linux/amd64 -t $(IMAGE):${TAG} -f $(DOCKERFILE_PATH) .
docker-push:
	docker push $(IMAGE):${TAG}
