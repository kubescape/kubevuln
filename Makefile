.PHONY: test all build clean

all: build

build:
	go build -v -o kubevuln ./cmd/http

test:
	go test -v ./...

clean:
	-rm -rf kubevuln
