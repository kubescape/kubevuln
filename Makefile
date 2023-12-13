DOCKERFILE_PATH=./build/Dockerfile
BINARY_NAME=kubevuln

IMAGE?=quay.io/kubescape/$(BINARY_NAME)
TAG=v0.0.0

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) cmd/http/main.go

docker-build:
	docker buildx build --platform linux/amd64 -t $(IMAGE):${TAG} -f $(DOCKERFILE_PATH) .
docker-push:
	docker push $(IMAGE):${TAG}
