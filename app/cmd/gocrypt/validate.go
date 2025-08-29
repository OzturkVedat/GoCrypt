package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func validate(cfg *Config) error {
	// basic checks
	if cfg.InPath == "" {
		return errors.New("input path is required")
	}
	if cfg.OutPath == "" {
		return errors.New("output path is required")
	}
	if len(cfg.Pass) == 0 {
		return errors.New("passphrase must not be empty")
	}
	if cfg.ChunkSize < minChunk || cfg.ChunkSize > maxChunk {
		return fmt.Errorf("chunk must be between %d and %d bytes", minChunk, maxChunk)
	}

	// input file must exist and be a regular file
	inInfo, err := os.Stat(cfg.InPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("input file %q does not exist", cfg.InPath)
		}
		return fmt.Errorf("cannot stat input file: %w", err)
	}
	if !inInfo.Mode().IsRegular() {
		return fmt.Errorf("input path %q is not a regular file", cfg.InPath)
	}

	// Resolve symlinks for input
	inPathResolved := cfg.InPath
	if p, err := filepath.EvalSymlinks(cfg.InPath); err == nil {
		inPathResolved = p
	}

	outDir := filepath.Dir(cfg.OutPath)
	outDirInfo, err := os.Stat(outDir)
	if err != nil {
		return fmt.Errorf("cannot access output directory %q: %w", outDir, err)
	}
	if !outDirInfo.IsDir() {
		return fmt.Errorf("output directory %q is not a directory", outDir)
	}

	// if output exists:
	if outInfo, err := os.Stat(cfg.OutPath); err == nil {
		// Compare in/out as same file (handles hard links)
		if os.SameFile(inInfo, outInfo) {
			return fmt.Errorf("input and output refer to the same file")
		}
		if !cfg.Force {
			return fmt.Errorf("output file %q already exists (use -force to overwrite)", cfg.OutPath)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cannot stat output path %q: %w", cfg.OutPath, err)
	}

	// also guard against same path via symlinks even if output doesn't exist yet
	inAbs, err := filepath.Abs(inPathResolved)
	if err != nil {
		return fmt.Errorf("cannot resolve absolute input path: %w", err)
	}
	outAbs, err := filepath.Abs(cfg.OutPath)
	if err != nil {
		return fmt.Errorf("cannot resolve absolute output path: %w", err)
	}
	if inAbs == outAbs {
		return fmt.Errorf("input and output paths resolve to the same location")
	}

	return nil
}
