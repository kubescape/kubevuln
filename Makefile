.PHONY: test all build clean grype

GRYPE_VERSION = "v0.56.0"

all: grype build

grype: anchore-resources/grype-cmd

anchore-resources/grype-cmd:
	rm -rf anchore-resources/grype
	git clone https://github.com/anchore/grype.git anchore-resources/grype --branch $(GRYPE_VERSION) --depth 1 2>/dev/null
	cd anchore-resources/grype && go build -v -o ../grype-cmd

build:
	go build -v .

test:
	go test -v ./...

clean:
	-rm -rf anchore-resources/grype-cmd
	-rm -rf anchore-resources/grype
	-rm -rf kubevuln
