package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/mholt/archives"
)

func main() {
	// Get environment variables
	awsAccessKeyID := os.Getenv("AWS_ACCESS_KEY_ID")
	awsSecretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	awsRegion := os.Getenv("AWS_REGION")
	bucketName := os.Getenv("S3_BUCKET_NAME")
	dataDir := os.Getenv("DATA_DIR")

	if awsAccessKeyID == "" || awsSecretAccessKey == "" || awsRegion == "" || bucketName == "" || dataDir == "" {
		log.Fatal("Missing required environment variables")
	}

	// Create tar.gz file
	tarFileName := fmt.Sprintf("backup-%s.tar.gz", time.Now().Format("2006-01-02-15-04-05"))

	// Create the archive file
	out, err := os.Create(tarFileName)
	if err != nil {
		log.Fatalf("Failed to create archive file: %v", err)
	}
	defer out.Close()
	defer os.Remove(tarFileName)

	// Map the data directory to be archived
	files, err := archives.FilesFromDisk(context.Background(), nil, map[string]string{
		dataDir: "", // Put contents at root of archive
	})
	if err != nil {
		log.Fatalf("Failed to prepare files for archiving: %v", err)
	}

	// Create a compressed tar archive
	format := archives.CompressedArchive{
		Compression: archives.Gz{},
		Archival:    archives.Tar{},
	}

	// Create the archive
	err = format.Archive(context.Background(), out, files)
	if err != nil {
		log.Fatalf("Failed to create archive: %v", err)
	}

	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(awsRegion),
	)
	if err != nil {
		log.Fatalf("Unable to load SDK config: %v", err)
	}

	// Create S3 client
	s3Client := s3.NewFromConfig(cfg)

	// Check if bucket exists
	_, err = s3Client.HeadBucket(context.TODO(), &s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		// Create bucket if it doesn't exist
		_, err = s3Client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
			Bucket: aws.String(bucketName),
			CreateBucketConfiguration: &types.CreateBucketConfiguration{
				LocationConstraint: types.BucketLocationConstraint(awsRegion),
			},
		})
		if err != nil {
			log.Fatalf("Unable to create bucket: %v", err)
		}
		log.Printf("Created bucket: %s\n", bucketName)

		// Enable versioning on the bucket
		_, err = s3Client.PutBucketVersioning(context.TODO(), &s3.PutBucketVersioningInput{
			Bucket: aws.String(bucketName),
			VersioningConfiguration: &types.VersioningConfiguration{
				Status: types.BucketVersioningStatusEnabled,
			},
		})
		if err != nil {
			log.Printf("Warning: Failed to enable versioning: %v", err)
		}
	}

	// Open the tar file for upload
	tarFile, err := os.Open(tarFileName)
	if err != nil {
		log.Fatalf("Failed to open tar file for upload: %v", err)
	}
	defer tarFile.Close()

	// Create uploader
	uploader := manager.NewUploader(s3Client)

	// Upload the tar file
	_, err = uploader.Upload(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(tarFileName),
		Body:   tarFile,
	})
	if err != nil {
		log.Fatalf("Failed to upload backup: %v", err)
	}

	log.Printf("Successfully uploaded backup to s3://%s/%s", bucketName, tarFileName)
}
