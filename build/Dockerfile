FROM golang:1.20-alpine as builder

ENV GO111MODULE=on CGO_ENABLED=0
WORKDIR /work

ADD go.mod go.sum /work/
RUN go mod download

ADD . .
RUN go build -o build/kubevuln cmd/http/main.go

FROM alpine

RUN addgroup -S ks && adduser -S ks -G ks
USER ks
WORKDIR /home/ks/

COPY --from=builder /work/build/kubevuln /usr/bin/kubevuln

ARG image_version
ENV RELEASE=$image_version

ENTRYPOINT ["kubevuln"]
