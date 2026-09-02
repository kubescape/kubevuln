FROM --platform=$BUILDPLATFORM golang:1.26-trixie AS builder

ENV GO111MODULE=on CGO_ENABLED=0
WORKDIR /work
ARG TARGETOS TARGETARCH

# -tags nodockerfixture excludes adapters/v1's testcontainers-go-backed grype-DB test fixture
# from the shipped kubevuln binary -- see Makefile's build target and #929.
RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -tags nodockerfixture -o /out/kubevuln cmd/http/main.go && \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/sbom-scanner cmd/sbom-scanner/main.go

FROM gcr.io/distroless/static-debian13:nonroot

USER nonroot
WORKDIR /home/nonroot/

COPY --from=builder /out/kubevuln /usr/bin/kubevuln
COPY --from=builder /out/sbom-scanner /usr/bin/sbom-scanner

ARG image_version
ENV RELEASE=$image_version

ENTRYPOINT ["kubevuln"]
