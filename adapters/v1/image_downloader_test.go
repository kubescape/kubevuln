package v1

import (
	"testing"
	"time"
)

func TestImageDownloader_DownloadImageAsTarball(t *testing.T) {
	// This is a basic test to verify the ImageDownloader can be instantiated
	// and the method signature is correct

	downloader := NewImageDownloader(1024*1024*100, time.Minute*5) // 100MB limit, 5min timeout

	if downloader == nil {
		t.Fatal("NewImageDownloader returned nil")
	}

	// Test with a simple public image (commented out to avoid network calls in tests)
	/*
		ctx := context.Background()
		imageID := "alpine:latest"
		imageTag := "alpine:latest"
		options := domain.RegistryOptions{
			Platform: "linux/amd64",
		}

		result, err := downloader.DownloadImageAsTarball(ctx, imageID, imageTag, options)
		if err != nil {
			t.Logf("Download failed (expected in test environment): %v", err)
			return
		}

		defer result.Cleanup()

		if result.TarballPath == "" {
			t.Error("Expected non-empty tarball path")
		}

		if result.ImageSize <= 0 {
			t.Error("Expected positive image size")
		}
	*/

	t.Log("ImageDownloader basic instantiation test passed")
}

func TestDiveAdapter_Integration(t *testing.T) {
	// Test that DiveAdapter can be created with the new ImageDownloader
	adapter := NewDiveAdapter("/usr/bin/dive", time.Minute*5, nil)

	if adapter == nil {
		t.Fatal("NewDiveAdapter returned nil")
	}

	if adapter.imageDownloader == nil {
		t.Error("DiveAdapter should have an imageDownloader instance")
	}

	t.Log("DiveAdapter integration test passed")
}

func TestTruffleHogAdapter_Integration(t *testing.T) {
	// Test that TruffleHogAdapter can be created with the new ImageDownloader
	adapter := NewTruffleHogAdapter("/usr/bin/trufflehog", time.Minute*5, nil)

	if adapter == nil {
		t.Fatal("NewTruffleHogAdapter returned nil")
	}

	if adapter.imageDownloader == nil {
		t.Error("TruffleHogAdapter should have an imageDownloader instance")
	}

	t.Log("TruffleHogAdapter integration test passed")
}
