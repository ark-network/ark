FROM debian:buster-slim

ARG TARGETPLATFORM

WORKDIR /app

COPY . .

RUN set -ex \
  && if [ "${TARGETPLATFORM}" = "linux/amd64" ]; then export TARGETPLATFORM=amd64; fi \
  && if [ "${TARGETPLATFORM}" = "linux/arm64" ]; then export TARGETPLATFORM=arm64; fi \
  && mv "coordinatord-linux-$TARGETPLATFORM" /usr/local/bin/coordinatord


# $USER name, and data $DIR to be used in the 'final' image
ARG USER=ark
ARG DIR=/home/ark

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates

# NOTE: Default GID == UID == 1000
RUN adduser --disabled-password \
            --home "$DIR/" \
            --gecos "" \
            "$USER"
USER $USER

# Prevents 'VOLUME $DIR/.coordinatord/' being created as owned by 'root'
RUN mkdir -p "$DIR/.coordinatord/"

# Expose volume containing all coordinatord data
VOLUME $DIR/.coordinatord/

ENTRYPOINT [ "coordinatord" ]
	