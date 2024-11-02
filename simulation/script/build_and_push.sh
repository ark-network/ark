#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Function to display usage information
usage() {
    echo "Usage: $0 -a <AWS_ACCOUNT_ID> -r <AWS_REGION> [-e <ECR_REPOSITORY_NAME>] [-i <IMAGE_NAME>] [-d <DOCKERFILE_PATH>] [-c <BUILD_CONTEXT>]"
    echo "  -a AWS Account ID"
    echo "  -r AWS Region"
    echo "  -e ECR Repository Name (default: client-repo)"
    echo "  -i Docker Image Name (default: client-image)"
    echo "  -d Dockerfile Path (default: current directory)"
    echo "  -c Build Context Path (default: current directory)"
    exit 1
}

# Default values
ECR_REPOSITORY_NAME="client-repo"
IMAGE_NAME="client-image"
DOCKERFILE_PATH="."
BUILD_CONTEXT="."  # Default build context is current directory

# Parse command-line arguments
while getopts "a:r:e:i:d:c:h" opt; do
    case $opt in
        a)
            AWS_ACCOUNT_ID="$OPTARG"
            ;;
        r)
            AWS_REGION="$OPTARG"
            ;;
        e)
            ECR_REPOSITORY_NAME="$OPTARG"
            ;;
        i)
            IMAGE_NAME="$OPTARG"
            ;;
        d)
            DOCKERFILE_PATH="$OPTARG"
            ;;
        c)
            BUILD_CONTEXT="$OPTARG"
            ;;
        h)
            usage
            ;;
        *)
            usage
            ;;
    esac
done

# Check if AWS_ACCOUNT_ID and AWS_REGION are set
if [ -z "$AWS_ACCOUNT_ID" ] || [ -z "$AWS_REGION" ]; then
    echo "Error: AWS Account ID and AWS Region are required."
    usage
fi

# Build the Docker image
echo "Building Docker image..."
docker build -t ${IMAGE_NAME} -f ${DOCKERFILE_PATH}/Dockerfile ${BUILD_CONTEXT}

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
