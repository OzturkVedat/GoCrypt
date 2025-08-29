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
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		die(err) // prints to stderr
	}
	defer zero(cfg.Pass) // schedule the cleanup for the end

	if err := validate(cfg); err != nil {
		die(err)
	}

	if fi, err := os.Stat(cfg.InPath); err == nil {
		log.Printf("Input: %s (%s)\n", filepath.Base(cfg.InPath), humanSize(fi.Size()))
	} else {
		log.Printf("Input: %s (stat error: %v)\n", cfg.InPath, err)
	}

	opt := engine.Options{
		InPath:    cfg.InPath,
		OutPath:   cfg.OutPath,
		Pass:      cfg.Pass,
		ChunkSize: cfg.ChunkSize,
	}

	start := time.Now() // start the timer
	var runErr error
	switch cfg.Mode {
	case "encrypt":
		runErr = engine.EncryptFile(opt)
	case "decrypt":
		runErr = engine.DecryptFile(opt)
	default:
		log.Fatalf("unknown mode %q", cfg.Mode)
	}

	elapsed := time.Since(start)
	log.Printf("%s took %s\n", cfg.Mode, elapsed)

	if runErr != nil {
		die(runErr)
	}
}
