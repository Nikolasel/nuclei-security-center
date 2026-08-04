package backend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Object storage (Phase 3). Raw Nuclei output (out.jsonl) is archived per scan
// to an S3-compatible bucket — MinIO locally, and any S3 API in the cloud (AWS
// S3, GCS in interop mode, MinIO). Postgres stays the system of record for the
// projected findings; the bucket holds the verbatim evidence, which is bulky and
// write-once, so object storage (not the DB) is its natural home.
//
// ObjectStore is a deliberately tiny interface so the rest of the backend never
// depends on the SDK directly: it keeps handlers testable (a fake in tests) and
// makes swapping the backend (e.g. gocloud.dev/blob for Azure) a localized change.

// ObjectStore is the minimal blob API the backend needs.
type ObjectStore interface {
	// Put stores size bytes read from r under key. size may be -1 when unknown.
	Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error
	// Get opens key for reading. It returns ErrObjectNotFound if the key is absent.
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	// Delete removes key. Removing an absent key is not an error (idempotent), so
	// a best-effort purge after deleting a scan stays simple.
	Delete(ctx context.Context, key string) error
}

// ErrObjectNotFound is returned by Get when the key does not exist.
var ErrObjectNotFound = errors.New("object not found")

// ObjectStoreConfig is the environment-driven config for the MinIO/S3 client.
// Archiving is enabled only when Endpoint is set.
type ObjectStoreConfig struct {
	Endpoint  string // host:port, no scheme (e.g. "minio:9000")
	Bucket    string // target bucket (created if absent)
	AccessKey string
	SecretKey string
	Region    string // default "us-east-1"
	UseSSL    bool
}

// minioStore is the S3-compatible ObjectStore backed by minio-go.
type minioStore struct {
	client *minio.Client
	bucket string
}

// NewObjectStore builds an ObjectStore from config and ensures the bucket exists.
// It returns (nil, nil) when cfg.Endpoint is empty — archiving is simply disabled,
// which is supported for local development independently of authentication.
func NewObjectStore(ctx context.Context, cfg ObjectStoreConfig) (ObjectStore, error) {
	if cfg.Endpoint == "" {
		return nil, nil
	}
	if cfg.Bucket == "" {
		return nil, errors.New("object store: bucket is required when endpoint is set")
	}
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}

	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  resolveCredentials(cfg),
		Secure: cfg.UseSSL,
		Region: region,
	})
	if err != nil {
		return nil, fmt.Errorf("object store: new client: %w", err)
	}

	if err := ensureBucket(ctx, client, cfg.Bucket, region); err != nil {
		return nil, err
	}
	return &minioStore{client: client, bucket: cfg.Bucket}, nil
}

// resolveCredentials chooses how to authenticate to the object store.
//
// When an explicit access key is configured, static V4 credentials are used —
// the local-dev path (MinIO) and any store that only takes keys (GCS, etc.).
// When the access key is empty, we fall back to the SDK's ambient credential
// chain: environment variables, the shared AWS credentials file, and the
// EC2/ECS/EKS instance-metadata IAM role. That lets a backend running on
// compute with an attached IAM role archive raw output without minting a
// long-lived IAM user + static keys just for this bucket. Per invariant #5 this
// is entirely a library capability (minio-go's credential providers) — no
// hand-rolled credential logic.
func resolveCredentials(cfg ObjectStoreConfig) *credentials.Credentials {
	if cfg.AccessKey != "" {
		return credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, "")
	}
	return credentials.NewChainCredentials([]credentials.Provider{
		&credentials.EnvAWS{},
		&credentials.EnvMinio{},
		&credentials.FileAWSCredentials{},
		&credentials.IAM{}, // EC2/ECS/EKS instance metadata; empty endpoint auto-detects
	})
}

// ensureBucket creates the bucket if absent, retrying so a MinIO/S3 endpoint
// that isn't ready the instant the backend boots (Compose start ordering)
// doesn't fail startup — mirroring the Postgres connect retry.
func ensureBucket(ctx context.Context, client *minio.Client, bucket, region string) error {
	const attempts = 15
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
		exists, err := client.BucketExists(ctx, bucket)
		if err != nil {
			lastErr = err
			continue
		}
		if exists {
			return nil
		}
		if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: region}); err != nil {
			// A racing creator (another replica) is fine.
			if exists2, e2 := client.BucketExists(ctx, bucket); e2 == nil && exists2 {
				return nil
			}
			lastErr = err
			continue
		}
		return nil
	}
	return fmt.Errorf("object store: ensure bucket %q after %d attempts: %w", bucket, attempts, lastErr)
}

func (m *minioStore) Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error {
	_, err := m.client.PutObject(ctx, m.bucket, key, r, size, minio.PutObjectOptions{ContentType: contentType})
	if err != nil {
		return fmt.Errorf("put %q: %w", key, err)
	}
	return nil
}

func (m *minioStore) Delete(ctx context.Context, key string) error {
	if err := m.client.RemoveObject(ctx, m.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("delete %q: %w", key, err)
	}
	return nil
}

func (m *minioStore) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	obj, err := m.client.GetObject(ctx, m.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("get %q: %w", key, err)
	}
	// minio defers the request until first read; probe so a missing key surfaces
	// as ErrObjectNotFound here rather than mid-stream.
	if _, err := obj.Stat(); err != nil {
		_ = obj.Close()
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, ErrObjectNotFound
		}
		return nil, fmt.Errorf("stat %q: %w", key, err)
	}
	return obj, nil
}
