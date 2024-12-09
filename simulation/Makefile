.PHONY: run build arkd push-to-ecr build-client run-web vet

#### Local simulation ####
## run: Run simulation locally Regtest
run:
	@echo "Running singe process simulation..."
	go run ./local/main.go $(ARGS)

## build:
build:
	@echo "Building simulation..."
	go build -o ./build/client ./local/client/main.go

## setup-ark:
setup-ark: arkd
	@echo "Setup arkd wallet..."
	./script/setup_arkd_wallet.sh

## arkd:
arkd:
	@echo "Starting arkd..."
	cd ../server && make run &

#### Remote simulation ####

# Default values for optional variables
ECR_REPOSITORY_NAME ?= ark-client-repo
IMAGE_NAME ?= arkclient
DOCKERFILE_PATH ?= ./web/client
BUILD_CONTEXT ?= ../

## push-to-ecr: Build and push client image to ECR
push-to-ecr:
	@echo "Building and pushing client image to ECR..."
	./script/build_and_push.sh -a $(AWS_ACCOUNT_ID) -r $(AWS_REGION) -e $(ECR_REPOSITORY_NAME) -i $(IMAGE_NAME) -d $(DOCKERFILE_PATH) -c $(BUILD_CONTEXT)

## build-client: Build Docker image only without pushing to ECR
build-client:
	@echo "Building Docker image without pushing to ECR..."
	./script/build_and_push.sh -a $(AWS_ACCOUNT_ID) -r $(AWS_REGION) -e $(ECR_REPOSITORY_NAME) -i $(IMAGE_NAME) -d $(DOCKERFILE_PATH) -c $(BUILD_CONTEXT) --no-push

## run-web: Run web interface for simulation
run-web:
	@echo "Starting web interface..."
	go run ./web/main.go $(ARGS)

#### Code Analysis ####
vet:
	@echo "Running go vet..."
	go vet ./...
