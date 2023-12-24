DOCKERFILE_PATH=./build/Dockerfile
BINARY_NAME=kubevuln

IMAGE?=quay.io/dwertent/$(BINARY_NAME)


build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) cmd/http/main.go

docker-build:
	docker buildx build --platform linux/amd64 -t $(IMAGE):$(TAG) -f $(DOCKERFILE_PATH) .
docker-push:
	docker push $(IMAGE):$(TAG)
