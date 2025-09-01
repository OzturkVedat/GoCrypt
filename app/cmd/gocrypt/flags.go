package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

type Config struct {
	Mode    string // "encrypt" or "decrypt"
	InPath  string
	OutPath string // populated by validate()
}

var (
	fMode = flag.String("mode", "", `encrypt|decrypt`)
	fIn   = flag.String("in", "", "input file path")
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gocrypt -mode encrypt|decrypt -in IN")
	flag.PrintDefaults()
}

func parseFlags() (*Config, error) {
	flag.Usage = usage
	flag.Parse()

	if *fMode != "encrypt" && *fMode != "decrypt" {
		usage()
		return nil, errors.New(`-mode must be "encrypt" or "decrypt"`)
	}
	if *fIn == "" {
		usage()
		return nil, errors.New("missing required -in")
	}

	cfg := &Config{
		Mode:   *fMode,
		InPath: *fIn,
	}
	return cfg, nil
}
