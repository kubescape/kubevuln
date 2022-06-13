FROM golang:1.18-alpine as builder

ENV RELEASE=$image_version

ENV GO111MODULE=

ENV CGO_ENABLED=0

WORKDIR /work
ADD . .

RUN apk add git

RUN go build -o build/vuln

RUN mkdir /work/vuln-scan

RUN git clone https://github.com/anchore/grype.git --branch v0.39.0 --depth 1
RUN cd grype && go build -o /work/vuln-scan/anchore-resources/grype-cmd

WORKDIR /work/vuln-scan

WORKDIR /work/vuln-scan/anchore-resources

RUN mkdir -m a=rwx .grype
COPY anchore-resources/.grype/config.yaml .grype/
RUN chmod 777 .grype/config.yaml
RUN chmod 777 grype-cmd
RUN chmod 777 -R /work/vuln-scan/anchore-resources

FROM alpine

RUN addgroup -S armo && adduser -S armo -G armo
USER armo
WORKDIR /home/armo/

COPY --from=builder /work/vuln-scan/ ./
COPY --from=builder /work/build/vuln /usr/bin/vuln


ENTRYPOINT ["vuln"]
