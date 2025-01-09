#!/bin/bash
set -e

cd ./otel
docker-compose -f docker-compose.otel.yaml up -d

sleep 5
echo "OpenTelemetry Collector running..."
