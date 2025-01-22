PHONY: build run

# Image name and tag
IMAGE_NAME ?= ark-backup
IMAGE_TAG ?= latest

# Default values for environment variables
AWS_ACCESS_KEY_ID ?= 
AWS_SECRET_ACCESS_KEY ?= 
AWS_REGION ?= eu-central-1
S3_BUCKET_NAME ?=

# Volume binding options (use one of these)
DATA_VOLUME ?= # Format: container_name:path or volume_name
LOCAL_PATH ?= # Format: /path/to/local/directory

# Build the Docker image
build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

# Run the backup container with environment variables and volume binding
run: build
	@if [ -z "$(AWS_ACCESS_KEY_ID)" ] || [ -z "$(AWS_SECRET_ACCESS_KEY)" ] || [ -z "$(S3_BUCKET_NAME)" ]; then \
		echo "Error: Required environment variables not set"; \
		echo "Required: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, S3_BUCKET_NAME"; \
		echo "Optional: AWS_REGION (default: us-east-1)"; \
		echo "Volume options (use one):"; \
		echo "  DATA_VOLUME (format: container_name:path or volume_name)"; \
		echo "  LOCAL_PATH (format: /path/to/local/directory)"; \
		exit 1; \
	fi
	@if [ -n "$(DATA_VOLUME)" ] && [ -n "$(LOCAL_PATH)" ]; then \
		echo "Error: Cannot specify both DATA_VOLUME and LOCAL_PATH"; \
		exit 1; \
	fi
	@if [ -n "$(DATA_VOLUME)" ]; then \
		docker run --rm \
			-e AWS_ACCESS_KEY_ID="$(AWS_ACCESS_KEY_ID)" \
			-e AWS_SECRET_ACCESS_KEY="$(AWS_SECRET_ACCESS_KEY)" \
			-e AWS_REGION="$(AWS_REGION)" \
			-e S3_BUCKET_NAME="$(S3_BUCKET_NAME)" \
			-e DATA_DIR="/data" \
			--volumes-from $(DATA_VOLUME) \
			$(IMAGE_NAME):$(IMAGE_TAG); \
	elif [ -n "$(LOCAL_PATH)" ]; then \
		if [ ! -d "$(LOCAL_PATH)" ]; then \
			echo "Error: Local directory $(LOCAL_PATH) does not exist"; \
			exit 1; \
		fi; \
		docker run --rm \
			-e AWS_ACCESS_KEY_ID="$(AWS_ACCESS_KEY_ID)" \
			-e AWS_SECRET_ACCESS_KEY="$(AWS_SECRET_ACCESS_KEY)" \
			-e AWS_REGION="$(AWS_REGION)" \
			-e S3_BUCKET_NAME="$(S3_BUCKET_NAME)" \
			-e DATA_DIR="/data" \
			-v "$(LOCAL_PATH):/data" \
			$(IMAGE_NAME):$(IMAGE_TAG); \
	else \
		echo "Error: Neither DATA_VOLUME nor LOCAL_PATH specified"; \
		echo "Use one of:"; \
		echo "  DATA_VOLUME=container_name:path"; \
		echo "  LOCAL_PATH=/path/to/local/directory"; \
		exit 1; \
	fi

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build              Build the Docker image"
	@echo "  run               Run the backup container"
	@echo "  help              Show this help message"
	@echo ""
	@echo "Environment variables:"
	@echo "  AWS_ACCESS_KEY_ID         AWS access key (required)"
	@echo "  AWS_SECRET_ACCESS_KEY     AWS secret key (required)"
	@echo "  AWS_REGION               AWS region (default: us-east-1)"
	@echo "  S3_BUCKET_NAME           S3 bucket name (required)"
	@echo ""
	@echo "Volume options (use one):"
	@echo "  DATA_VOLUME              Container or volume to backup"
	@echo "  LOCAL_PATH               Local directory to backup"
	@echo ""
	@echo "Example usage:"
	@echo "  make build"
	@echo "  # Backup from another container:"
	@echo "  make run AWS_ACCESS_KEY_ID=key AWS_SECRET_ACCESS_KEY=secret S3_BUCKET_NAME=my-bucket DATA_VOLUME=myapp:/app/data"
	@echo ""
	@echo "  # Backup from local directory:"
	@echo "  make run AWS_ACCESS_KEY_ID=key AWS_SECRET_ACCESS_KEY=secret S3_BUCKET_NAME=my-bucket LOCAL_PATH=/path/to/backup"
