FROM golang:1.18-alpine as builder

ENV RELEASE=$image_version

ENV GO111MODULE=

ENV CGO_ENABLED=0

WORKDIR /work
ADD . .

RUN apk add git

WORKDIR /work
RUN go build -o build/vuln

RUN mkdir -p vuln-scan
WORKDIR /work/vuln-scan
RUN mkdir -m a=rwx anchore-resources
COPY ./grype-binaries/grype-cmd ./anchore-resources/
WORKDIR /work/vuln-scan/anchore-resources
RUN mkdir -m a=rwx .grype
COPY anchore-resources/.grype/config.yaml .grype/
RUN chmod 444 .grype/config.yaml
RUN chmod 111 grype-cmd

FROM alpine

RUN addgroup -S armo && adduser -S armo -G armo
USER armo
WORKDIR /home/armo/

COPY --from=builder /work/vuln-scan/ ./
COPY --from=builder /work/build/vuln /usr/bin/vuln

ENTRYPOINT ["vuln"]
