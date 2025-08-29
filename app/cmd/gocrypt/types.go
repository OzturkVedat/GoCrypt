package main

type Config struct {
	Mode      string
	InPath    string
	OutPath   string
	Pass      []byte
	ChunkSize uint32
	Force     bool
	ShowVer   bool
}

const (
	defaultChunk = 1 << 20  // 1 MiB
	minChunk     = 4 << 10  // 4 KiB
	maxChunk     = 64 << 20 // 64 MiB
)
