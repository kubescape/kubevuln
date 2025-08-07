package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	v1 "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/core/domain"
)

func main() {
	// Define command line flags
	var (
		imageTag       = flag.String("image", "", "Docker image tag to scan (e.g., nginx:latest)")
		timeout        = flag.Duration("timeout", 5*time.Minute, "Scan timeout")
		maxImageSize   = flag.Int64("max-image-size", 512*1024*1024, "Maximum image size in bytes")
		maxSBOMSize    = flag.Int("max-sbom-size", 20*1024*1024, "Maximum SBOM size in bytes")
		scanEmbedded   = flag.Bool("scan-embedded", false, "Scan for embedded SBOMs")
		skipDive       = flag.Bool("skip-dive", false, "Skip dive scan (layer analysis)")
		skipTruffleHog = flag.Bool("skip-trufflehog", false, "Skip trufflehog scan (secret detection)")
		async          = flag.Bool("async", false, "Run scans asynchronously (don't wait for dive/trufflehog)")
		help           = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	if *help {
		fmt.Println("KubeVuln CLI - Container Image Vulnerability Scanner")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  kubevuln -image <image-tag> [options]")
		fmt.Println()
		fmt.Println("Options:")
		flag.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  kubevuln -image nginx:latest")
		fmt.Println("  kubevuln -image alpine:latest -skip-dive")
		fmt.Println("  kubevuln -image ubuntu:20.04 -timeout 10m")
		fmt.Println("  kubevuln -image nginx:latest -async")
		fmt.Println("  kubevuln -image nginx:latest -skip-trufflehog")
		return
	}

	if *imageTag == "" {
		fmt.Println("❌ Error: Image tag is required")
		fmt.Println("Use -help for usage information")
		os.Exit(1)
	}

	fmt.Printf("=== KubeVuln CLI Scan ===\n")
	fmt.Printf("🔍 Scanning image: %s\n", *imageTag)
	fmt.Printf("⏱️  Timeout: %v\n", *timeout)
	fmt.Printf("📦 Max image size: %d MB\n", *maxImageSize/(1024*1024))
	fmt.Printf("📋 Max SBOM size: %d MB\n", *maxSBOMSize/(1024*1024))
	fmt.Printf("🔍 Scan embedded SBOMs: %v\n", *scanEmbedded)
	fmt.Printf("⏳ Skip dive: %v\n", *skipDive)
	fmt.Printf("🔐 Skip trufflehog: %v\n", *skipTruffleHog)
	fmt.Printf("🔄 Run scans asynchronously: %v\n", *async)
	fmt.Println()

	// Create syft adapter with dive integration
	syftAdapter := v1.NewSyftAdapter(*timeout, *maxImageSize, *maxSBOMSize, *scanEmbedded)

	// Use normalized image name for dive file matching
	imageName := normalizeImageName(*imageTag)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Start the scan
	startTime := time.Now()
	fmt.Printf("🚀 Starting scan...\n")

	sbom, err := syftAdapter.CreateSBOM(ctx, imageName, "", *imageTag, domain.RegistryOptions{})
	if err != nil {
		fmt.Printf("❌ Scan failed: %v\n", err)
		os.Exit(1)
	}

	duration := time.Since(startTime)
	fmt.Printf("✅ SBOM generation completed in %v!\n", duration)
	fmt.Printf("📊 Status: %s\n", sbom.Status)
	fmt.Printf("📦 Packages found: %d\n", len(sbom.Content.Artifacts))

	if *skipDive {
		fmt.Println()
		fmt.Println("💡 Dive scan is skipped")
	} else if *async {
		fmt.Println()
		fmt.Println("💡 Dive scan is running asynchronously in the background")
	} else {
		fmt.Println()
		fmt.Println("⏳ Waiting for dive scan to complete...")

		// Wait for dive results (reduced to 3 minutes = 18 iterations of 10 seconds)
		for i := 0; i < 18; i++ {
			time.Sleep(10 * time.Second)

			// Check for dive results
			diveFile := findMostRecentDiveFile(imageName)
			if diveFile != "" {
				fmt.Printf("✅ Dive scan completed! Results saved to: %s\n", diveFile)
				fmt.Printf("📊 File size: %d bytes\n", getFileSize(diveFile))
				break
			}

			if i == 17 {
				fmt.Println("⚠️  Dive scan did not complete within 3 minutes")
			}
		}
	}

	if *skipTruffleHog {
		fmt.Println()
		fmt.Println("🔐 TruffleHog scan is skipped")
	} else if *async {
		fmt.Println()
		fmt.Println("🔐 TruffleHog scan is running asynchronously in the background")
	} else {
		fmt.Println()
		fmt.Println("⏳ Waiting for trufflehog scan to complete...")

		// Wait for trufflehog results (reduced to 3 minutes = 18 iterations of 10 seconds)
		for i := 0; i < 18; i++ {
			time.Sleep(10 * time.Second)

			// Check for trufflehog results
			truffleHogFile := findMostRecentTruffleHogFile(imageName)
			if truffleHogFile != "" {
				fmt.Printf("✅ TruffleHog scan completed! Results saved to: %s\n", truffleHogFile)
				fmt.Printf("📊 File size: %d bytes\n", getFileSize(truffleHogFile))
				break
			}

			if i == 17 {
				fmt.Println("⚠️  TruffleHog scan did not complete within 3 minutes")
			}
		}
	}

	fmt.Println()
	fmt.Println("🎉 Scan completed successfully!")
}

// normalizeImageName mimics the logic used by the adapters for dive file naming
func normalizeImageName(imageTag string) string {
	name := imageTag
	name = strings.ReplaceAll(name, ":", "-")
	name = strings.ReplaceAll(name, "/", "-")
	if !strings.Contains(name, "-nohash") {
		name = name + "-nohash"
	}
	return name
}

// findMostRecentDiveFile searches for the most recent dive file for the given image
func findMostRecentDiveFile(imageName string) string {
	diveResultsDir := "./dive-results"
	if _, err := os.Stat(diveResultsDir); os.IsNotExist(err) {
		return ""
	}
	files, err := os.ReadDir(diveResultsDir)
	if err != nil {
		logger.L().Warning("Could not read dive-results directory", helpers.Error(err))
		return ""
	}
	var diveFiles []string
	for _, file := range files {
		if !file.IsDir() {
			fileName := file.Name()
			if strings.HasPrefix(fileName, imageName) && strings.HasSuffix(fileName, "-dive.json") {
				diveFiles = append(diveFiles, diveResultsDir+"/"+fileName)
			}
		}
	}
	if len(diveFiles) == 0 {
		fmt.Printf("🔍 No dive files found for %s\n", imageName)
		fmt.Printf("   Available dive files:\n")
		for _, file := range files {
			if !file.IsDir() && strings.HasSuffix(file.Name(), "-dive.json") {
				fmt.Printf("   - %s\n", file.Name())
			}
		}
		return ""
	}
	// Sort files by modification time (most recent first)
	type fileInfoWithPath struct {
		path    string
		modTime time.Time
	}
	var fileInfos []fileInfoWithPath
	for _, f := range diveFiles {
		info, err := os.Stat(f)
		if err == nil {
			fileInfos = append(fileInfos, fileInfoWithPath{f, info.ModTime()})
		}
	}
	if len(fileInfos) == 0 {
		return ""
	}
	sort.Slice(fileInfos, func(i, j int) bool {
		return fileInfos[i].modTime.After(fileInfos[j].modTime)
	})
	return fileInfos[0].path
}

// findMostRecentTruffleHogFile searches for the most recent trufflehog file for the given image
func findMostRecentTruffleHogFile(imageName string) string {
	truffleHogResultsDir := "./trufflehog-results"
	if _, err := os.Stat(truffleHogResultsDir); os.IsNotExist(err) {
		return ""
	}
	files, err := os.ReadDir(truffleHogResultsDir)
	if err != nil {
		logger.L().Warning("Could not read trufflehog-results directory", helpers.Error(err))
		return ""
	}
	var truffleHogFiles []string
	for _, file := range files {
		if !file.IsDir() {
			fileName := file.Name()
			if strings.HasPrefix(fileName, imageName) && strings.HasSuffix(fileName, "-trufflehog.json") {
				truffleHogFiles = append(truffleHogFiles, truffleHogResultsDir+"/"+fileName)
			}
		}
	}
	if len(truffleHogFiles) == 0 {
		fmt.Printf("🔍 No trufflehog files found for %s\n", imageName)
		fmt.Printf("   Available trufflehog files:\n")
		for _, file := range files {
			if !file.IsDir() && strings.HasSuffix(file.Name(), "-trufflehog.json") {
				fmt.Printf("   - %s\n", file.Name())
			}
		}
		return ""
	}
	// Sort files by modification time (most recent first)
	type fileInfoWithPath struct {
		path    string
		modTime time.Time
	}
	var fileInfos []fileInfoWithPath
	for _, f := range truffleHogFiles {
		info, err := os.Stat(f)
		if err == nil {
			fileInfos = append(fileInfos, fileInfoWithPath{f, info.ModTime()})
		}
	}
	if len(fileInfos) == 0 {
		return ""
	}
	sort.Slice(fileInfos, func(i, j int) bool {
		return fileInfos[i].modTime.After(fileInfos[j].modTime)
	})
	return fileInfos[0].path
}

// getFileSize returns the size of a file in bytes
func getFileSize(filepath string) int64 {
	info, err := os.Stat(filepath)
	if err != nil {
		return 0
	}
	return info.Size()
}
