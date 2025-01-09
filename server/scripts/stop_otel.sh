#!/bin/bash
set -e

cd ./otel
docker-compose -f docker-compose.otel.yaml stop

echo "OpenTelemetry Collector containers stopped."
