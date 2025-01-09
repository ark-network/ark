#!/bin/bash
set -e

cd ./otel
docker-compose -f docker-compose.otel.yaml down -v

echo "All containers and volumes removed."