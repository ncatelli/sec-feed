ARG BASEIMG="alpine:3.15"
ARG BUILDIMG="golang:1.18-alpine3.15"
FROM $BUILDIMG as builder

ARG APP_NAME="sec-feed"
ENV GOPATH=""
ENV CGO_ENABLED=0 

RUN apk --no-cache add git

COPY . /go/

RUN cd /go \
    && CGO_ENABLED=0 go build -o /${APP_NAME}

FROM $BASEIMG
LABEL maintainer="Nate Catelli <ncatelli@packetfire.org>"
LABEL description="Container for sec-feed"

ARG SERVICE_USER="service"
ARG APP_NAME="sec-feed"

RUN addgroup ${SERVICE_USER} \
    && adduser -D -G ${SERVICE_USER} ${SERVICE_USER}

COPY --from=builder /${APP_NAME} /opt/${APP_NAME}/bin/${APP_NAME}

RUN mkdir -p /opt/${APP_NAME}/.${APP_NAME}/cache \
    && chown ${SERVICE_USER}:${SERVICE_USER}  /opt/${APP_NAME}/.${APP_NAME}/cache \
    && chown ${SERVICE_USER}:${SERVICE_USER} /opt/${APP_NAME}/bin/${APP_NAME} \
    && chmod +x /opt/${APP_NAME}/bin/${APP_NAME}

VOLUME /opt/${APP_NAME}/.${APP_NAME}/cache

WORKDIR "/opt/${APP_NAME}/"
USER ${SERVICE_USER}

ENTRYPOINT [ "/opt/sec-feed/bin/sec-feed" ]
CMD [ "-h" ]
