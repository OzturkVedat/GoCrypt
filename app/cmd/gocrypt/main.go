package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"gocrypt/internal/engine"
)

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	// human readable file size
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func die(err error) {
	log.SetFlags(0)
	log.Printf("error: %v", err)
	os.Exit(1)
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		die(err)
	}

	if err := validate(cfg); err != nil {
		die(err)
	}

	if fi, err := os.Stat(cfg.InPath); err == nil {
		log.Printf("Input:  %s (%s)", filepath.Base(cfg.InPath), humanSize(fi.Size()))
	} else {
		log.Printf("Input:  %s (stat error: %v)", cfg.InPath, err)
	}
	log.Printf("Output: %s", filepath.Base(cfg.OutPath))

	opt := engine.Options{
		InPath:  cfg.InPath,
		OutPath: cfg.OutPath,
	}

	start := time.Now()
	var runErr error

	switch cfg.Mode {
	case "encrypt":
		runErr = engine.EncryptFile(opt)
	case "decrypt":
		runErr = engine.DecryptFile(opt)
	default:
		die(fmt.Errorf("unknown mode %q", cfg.Mode))
	}

	if runErr != nil {
		die(runErr)
	}

	elapsed := time.Since(start)
	switch cfg.Mode {
	case "encrypt":
		log.Printf("Encryption took %s", elapsed)
	case "decrypt":
		log.Printf("Decryption took %s", elapsed)
	}
}
