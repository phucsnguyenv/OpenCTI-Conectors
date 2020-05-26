FROM python:3.8-alpine
LABEL maintainer="phucsnguyenv@gmail.com"
LABEL base.name="connector-internal-import" \
    base.version=${VERSION}

ARG VERSION=unknown

COPY src /opt/opencti-connector-internal-import

RUN apk --no-cache add git build-base libmagic && \
    cd /opt/opencti-connector-internal-import && \
    pip3 install --no-cache-dir git+https://github.com/OpenCTI-Platform/client-python@master && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT [ "/entrypoint.sh" ]