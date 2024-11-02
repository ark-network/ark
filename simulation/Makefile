.PHONY: buildclient run push-to-ecr

#### Remote simulation ####

# Default values for optional variables
SIMULATION ?= simulation1.yaml
ECR_REPOSITORY_NAME ?= client-repo
IMAGE_NAME ?= client-image
DOCKERFILE_PATH ?= ./remote/client
BUILD_CONTEXT ?= ../

## push-to-ecr: Build and push client image to ECR
push-to-ecr:
	@echo "Building and pushing client image to ECR..."
	./script/build_and_push.sh -a $(AWS_ACCOUNT_ID) -r $(AWS_REGION) -e $(ECR_REPOSITORY_NAME) -i $(IMAGE_NAME) -d $(DOCKERFILE_PATH) -c $(BUILD_CONTEXT)
