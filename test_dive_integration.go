package main

import (
	"context"
	"fmt"
	"log"
	"time"

	v1 "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/core/domain"
)

func main() {
	fmt.Println("Testing Dive Integration with nginx image...")

	// Create a syft adapter with dive integration
	syftAdapter := v1.NewSyftAdapter(5*time.Minute, 512*1024*1024, 20*1024*1024, false)

	// Test with nginx image
	imageTag := "nginx:latest"
	imageName := "nginx"

	fmt.Printf("Scanning image: %s\n", imageTag)

	// Create SBOM (this will also trigger dive scan)
	ctx := context.Background()
	sbom, err := syftAdapter.CreateSBOM(ctx, imageName, "", imageTag, domain.RegistryOptions{})

	if err != nil {
		log.Fatalf("Failed to create SBOM: %v", err)
	}

	fmt.Printf("SBOM created successfully!\n")
	fmt.Printf("Status: %s\n", sbom.Status)
	fmt.Printf("Packages found: %d\n", len(sbom.Content.Artifacts))

	// Wait a bit for dive to complete
	fmt.Println("Waiting for dive scan to complete...")
	time.Sleep(10 * time.Second)

	// Check if dive results were created
	fmt.Println("Checking for dive results...")
	fmt.Println("Look for files in ./dive-results/ directory")

	fmt.Println("Test completed!")
}
