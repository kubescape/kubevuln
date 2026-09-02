DOCKERFILE_PATH=./build/Dockerfile
BINARY_NAME=kubevuln

IMAGE?=quay.io/kubescape/$(BINARY_NAME)
TAG=v0.0.0

.PHONY: build test vet lint lint-all verify verify-image govulncheck

# nodockerfixture excludes adapters/v1/grype_docker_fixture.go's testcontainers-go-backed
# grype-DB test fixture from the shipped binary -- `go test` (below, untagged) still compiles
# and runs it exactly as before. See #929: without this, testcontainers-go's own docker/docker
# dependency was shipped in a binary that never actually calls it, keeping the binary's
# govulncheck scan permanently red over CVEs it can never reach.
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags nodockerfixture -o $(BINARY_NAME) cmd/http/main.go

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

# Queries vuln.go.dev, so it's kept out of `verify`'s fast local path (see #854).
# Binary mode scans the actual compiled artifact rather than source, so the
# result reflects what's really shipped (build tags, dead-code elimination).
govulncheck: build
	govulncheck -mode=binary $(BINARY_NAME)

verify: build test vet lint

verify-image: docker-build

docker-build:
	docker buildx build --platform linux/amd64 -t $(IMAGE):${TAG} -f $(DOCKERFILE_PATH) .
docker-push:
	docker push $(IMAGE):${TAG}
