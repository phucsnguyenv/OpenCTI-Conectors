FROM python:3.8-alpine
LABEL maintainer="phucsnguyenv@gmail.com"

COPY src /opt/opencti-connector-talosip

RUN apk --no-cache add git build-base libmagic && \
    cd /opt/opencti-connector-talosip && \
    pip3 install --no-cache-dir git+https://github.com/OpenCTI-Platform/client-python@master && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

COPY entrypoint.sh /
ONBUILD RUN ls -la /opt/opencti-connector-talosip
RUN chmod +x /entrypoint.sh
ENTRYPOINT [ "/entrypoint.sh" ]

