FROM registry.access.redhat.com/ubi8/ubi

LABEL description="Armo image scanner connector - this image is part of the CyberArmor operator deployment and it is not meant to be used alone"
LABEL name="Armo image scanner connector"
LABEL summary="Armo image scanner connector image"
LABEL vendor="Armo Ltd."

COPY ./dist /.
COPY ./build_number.txt /

RUN echo $(date -u) > /tmp/build_date.txt
ENTRYPOINT ["./k8s-ca-vuln-scan"]
