FROM --platform=$BUILDPLATFORM golang:1.20-alpine as builder

ENV GO111MODULE=on CGO_ENABLED=0
WORKDIR /work
ARG TARGETOS TARGETARCH

RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/kubevuln cmd/http/main.go

FROM alpine

RUN addgroup -S ks && adduser -S ks -G ks
USER ks
WORKDIR /home/ks/

COPY --from=builder /out/kubevuln /usr/bin/kubevuln

ARG image_version
ENV RELEASE=$image_version

ENTRYPOINT ["kubevuln"]
