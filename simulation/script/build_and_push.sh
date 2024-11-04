#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Function to display usage information
usage() {
    echo "Usage: $0 -a <AWS_ACCOUNT_ID> -r <AWS_REGION> [-e <ECR_REPOSITORY_NAME>] [-i <IMAGE_NAME>] [-d <DOCKERFILE_PATH>] [-c <BUILD_CONTEXT>] [--no-push]"
    echo "  -a AWS Account ID"
    echo "  -r AWS Region"
    echo "  -e ECR Repository Name (default: client-repo)"
    echo "  -i Docker Image Name (default: client-image)"
    echo "  -d Dockerfile Path (default: current directory)"
    echo "  -c Build Context Path (default: current directory)"
    echo "  --no-push Skip pushing the Docker image to ECR"
    exit 1
}

# Default values
ECR_REPOSITORY_NAME="client-repo"
IMAGE_NAME="client-image"
DOCKERFILE_PATH="."
BUILD_CONTEXT="."
NO_PUSH=false  # Default to pushing image

# Parse command-line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -a) AWS_ACCOUNT_ID="$2"; shift ;;
        -r) AWS_REGION="$2"; shift ;;
        -e) ECR_REPOSITORY_NAME="$2"; shift ;;
        -i) IMAGE_NAME="$2"; shift ;;
        -d) DOCKERFILE_PATH="$2"; shift ;;
        -c) BUILD_CONTEXT="$2"; shift ;;
        --no-push) NO_PUSH=true ;;
        -h|--help) usage ;;
        *) usage ;;
    esac
    shift
done

# Check if AWS_ACCOUNT_ID and AWS_REGION are set
if [ "$NO_PUSH" = false ]; then
    # Check if AWS_ACCOUNT_ID and AWS_REGION are set
    if [ -z "$AWS_ACCOUNT_ID" ] || [ -z "$AWS_REGION" ]; then
        echo "Error: AWS Account ID and AWS Region are required."
        usage
    fi
fi

# Build the Docker image
echo "Building Docker image..."
docker build --build-arg TARGETOS=linux --build-arg TARGETARCH=$(uname -m) -t ${IMAGE_NAME} -f ${DOCKERFILE_PATH}/Dockerfile ${BUILD_CONTEXT}

# Skip pushing if --no-push is set
if [ "$NO_PUSH" = true ]; then
    echo "Skipping ECR push as per --no-push flag."
    exit 0
fi

# Authenticate Docker to ECR
echo "Authenticating Docker to ECR..."
aws ecr get-login-password --region ${AWS_REGION} | \
docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

# Create ECR repository if it doesn't exist
echo "Checking if ECR repository exists..."
aws ecr describe-repositories --repository-names "${ECR_REPOSITORY_NAME}" --region ${AWS_REGION} > /dev/null 2>&1 || \
{
    echo "ECR repository doesn't exist. Creating..."
    aws ecr create-repository --repository-name "${ECR_REPOSITORY_NAME}" --region ${AWS_REGION}
}

# Tag the Docker image
echo "Tagging Docker image..."
docker tag ${IMAGE_NAME}:latest ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPOSITORY_NAME}:latest

# Push the Docker image to ECR
echo "Pushing Docker image to ECR..."
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPOSITORY_NAME}:latest

echo "Docker image pushed to ECR successfully."
