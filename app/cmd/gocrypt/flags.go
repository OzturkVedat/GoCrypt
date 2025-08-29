package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

var (
	fMode    = flag.String("mode", "", "encrypt|decrypt")
	fIn      = flag.String("in", "", "input file path")
	fOut     = flag.String("out", "", "output file path")
	fChunk   = flag.Uint("chunk", 0, "chunk size (bytes; default 1 MiB)")
	fForce   = flag.Bool("force", false, "overwrite output if it exists")
	fVersion = flag.Bool("version", false, "print version and exit")
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: qforge -mode encrypt|decrypt -in IN -out OUT [-chunk N] [-force]")
	fmt.Fprintln(os.Stderr, "\npassphrase is read from the environment variable QFORGE_PASS (auto-loaded from .env if present)")
	flag.PrintDefaults()
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func parseFlags() (*Config, error) {
	flag.Usage = usage
	flag.Parse()

	_ = godotenv.Load()

	if *fVersion {
		fmt.Fprintln(os.Stderr, "qforge 1.0.0")
		os.Exit(0)
	}

	if *fMode != "encrypt" && *fMode != "decrypt" {
		usage()
		os.Exit(2)
	}
	if *fIn == "" || *fOut == "" {
		usage()
		os.Exit(2)
	}

	pw := os.Getenv("QFORGE_PASS")
	if pw == "" {
		return nil, fmt.Errorf("missing passphrase: set QFORGE_PASS in the environment")
	}

	ch := *fChunk
	if ch == 0 {
		ch = defaultChunk
	}

	cfg := &Config{
		Mode:      *fMode,
		InPath:    *fIn,
		OutPath:   *fOut,
		Pass:      []byte(pw),
		ChunkSize: uint32(ch),
		Force:     *fForce,
		ShowVer:   *fVersion,
	}
	return cfg, nil
}

func zero(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}
