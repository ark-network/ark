.PHONY: run push-to-ecr build-client

#### Remote simulation ####

# Default values for optional variables
ECR_REPOSITORY_NAME ?= ark-client-repo
IMAGE_NAME ?= arkclient
DOCKERFILE_PATH ?= ./remote/client
BUILD_CONTEXT ?= ../

## push-to-ecr: Build and push client image to ECR
push-to-ecr:
	@echo "Building and pushing client image to ECR..."
	./script/build_and_push.sh -a $(AWS_ACCOUNT_ID) -r $(AWS_REGION) -e $(ECR_REPOSITORY_NAME) -i $(IMAGE_NAME) -d $(DOCKERFILE_PATH) -c $(BUILD_CONTEXT)

## build-client: Build Docker image only without pushing to ECR
build-client:
	@echo "Building Docker image without pushing to ECR..."
	./script/build_and_push.sh -a $(AWS_ACCOUNT_ID) -r $(AWS_REGION) -e $(ECR_REPOSITORY_NAME) -i $(IMAGE_NAME) -d $(DOCKERFILE_PATH) -c $(BUILD_CONTEXT) --no-push