.PHONY: run push-to-ecr build-client

#### Local simulation ####
## run-single: Run bundled simulation where client and server are in the same process
run-single:
	@echo "Running singe process simulation..."
	go run ./local/single-process/main.go

## run-multi: Run simulation with separate client and server processes
run-multi: build-local-client
	@echo "Running multi-process simulation..."
	go run ./local/process-per-client/main.go

## build-local-client
build-local-client:
	@echo "Building local client..."
	go build -o ./build/client ./local/process-per-client/client/main.go

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

## run-remote: Run simulation on remote server
run-remote:
	@echo "Running simulation on remote server..."
	@if [ -z "$(SUBNET_IDS)" ]; then \
		echo "Error: SUBNET_IDS is not set. You can find this in CloudFormation outputs."; \
		exit 1; \
	fi
	@if [ -z "$(SECURITY_GROUP_IDS)" ]; then \
		echo "Error: SECURITY_GROUP_IDS is not set. You can find this in CloudFormation outputs."; \
		exit 1; \
	fi
	go run ./remote/orchestrator/main.go