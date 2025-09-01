package engine

import (
	"os"
	"runtime"
)

type Options struct {
	InPath    string
	OutPath   string
	Pass      []byte
	ChunkSize uint32
	Workers   int
}

// Upper/lower bounds; MaxAcceptedChunk is from engine.go
const (
	defaultChunk    uint32 = 16 * 1024 * 1024 // used if size unknown
	minChunk        uint32 = 256 * 1024       // 256 KiB floor
	chunkAlign      uint32 = 64 * 1024        // round up to 64 KiB
	targetPerWorker        = 32               // aim ~32 chunks per worker
)

func AutoAdjust(opt Options) Options {
	if opt.Workers <= 0 {
		n := runtime.NumCPU()
		if n <= 2 {
			opt.Workers = 1
		} else {
			opt.Workers = n
		}
	}

	var size int64 = -1
	if fi, err := os.Stat(opt.InPath); err == nil {
		size = fi.Size()
	}

	if opt.ChunkSize == 0 {
		if size > 0 {
			opt.ChunkSize = pickChunkSize(size, opt.Workers)
		} else {
			opt.ChunkSize = defaultChunk
		}
	}

	// if the file is very small, cap workers to number of chunks
	if size > 0 {
		nChunks := (size + int64(opt.ChunkSize) - 1) / int64(opt.ChunkSize)
		if nChunks > 0 && int64(opt.Workers) > nChunks {
			opt.Workers = int(nChunks)
			if opt.Workers == 0 {
				opt.Workers = 1
			}
		}
	}

	return opt
}

func pickChunkSize(fileSize int64, workers int) uint32 {
	if workers <= 0 {
		workers = 1
	}
	// target total chunks ≈ workers * targetPerWorker
	targetChunks := int64(workers * targetPerWorker)
	chunk := fileSize / targetChunks
	if chunk <= 0 {
		chunk = int64(minChunk)
	}
	if chunk < int64(minChunk) {
		chunk = int64(minChunk)
	}
	if MaxAcceptedChunk > 0 && chunk > int64(MaxAcceptedChunk) {
		chunk = int64(MaxAcceptedChunk)
	}

	// round up to alignment (helps filesystem)
	align := int64(chunkAlign)
	chunk = ((chunk + align - 1) / align) * align

	// final guard
	if chunk <= 0 {
		return defaultChunk
	}
	if chunk > int64(^uint32(0)) {
		return MaxAcceptedChunk
	}
	return uint32(chunk)
}
