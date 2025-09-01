package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	encExt   = ".enc"
	maxBytes = 5 * 1024 * 1024 * 1024 // 5 GiB
)

func deriveOut(mode, inAbs string) (string, error) {
	switch mode {
	case "encrypt":
		return inAbs + encExt, nil
	case "decrypt":
		if !strings.HasSuffix(inAbs, encExt) {
			return "", errors.New("decrypt requires input file to end with .enc")
		}
		return inAbs[:len(inAbs)-len(encExt)], nil
	default:
		return "", fmt.Errorf("unknown mode %q", mode)
	}
}

func validate(cfg *Config) error {
	if cfg.Mode != "encrypt" && cfg.Mode != "decrypt" {
		return errors.New(`-mode must be "encrypt" or "decrypt"`)
	}
	if cfg.InPath == "" {
		return errors.New("input path is required (-in)")
	}

	// Resolve input to absolute and validate type
	inAbs, err := filepath.Abs(cfg.InPath)
	if err != nil {
		return fmt.Errorf("abs(%s): %w", cfg.InPath, err)
	}
	fi, err := os.Lstat(inAbs)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("input file %q does not exist", inAbs)
		}
		return fmt.Errorf("cannot stat input file: %w", err)
	}

	// Only operate on regular files; reject symlinks/dirs/devices
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("input is a symlink: %s (refusing to follow)", inAbs)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("input path %q is not a regular file", inAbs)
	}
	if fi.Size() > maxBytes {
		return fmt.Errorf("input file %q is too large (%d bytes > 10 GiB limit)", inAbs, fi.Size())
	}

	outAbs, err := deriveOut(cfg.Mode, inAbs)
	if err != nil {
		return err
	}

	// Output directory must exist and be a directory
	outDir := filepath.Dir(outAbs)
	outDirInfo, err := os.Stat(outDir)
	if err != nil {
		return fmt.Errorf("cannot access output directory %q: %w", outDir, err)
	}
	if !outDirInfo.IsDir() {
		return fmt.Errorf("output directory %q is not a directory", outDir)
	}

	// Refuse to overwrite existing output
	if outInfo, err := os.Stat(outAbs); err == nil {
		// Also guard against same-file via hard links
		if os.SameFile(fi, outInfo) {
			return errors.New("input and output refer to the same file")
		}
		return fmt.Errorf("output file %q already exists (overwrite disabled)", outAbs)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cannot stat output path %q: %w", outAbs, err)
	}

	// Final guard: identical absolute paths (covers non-existent output case)
	if inAbs == outAbs {
		return errors.New("input and output resolve to the same path")
	}

	// Normalize back into cfg for downstream use
	cfg.InPath = inAbs
	cfg.OutPath = outAbs
	return nil
}
