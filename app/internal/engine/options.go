package engine

type Options struct {
	InPath    string
	OutPath   string
	Pass      []byte
	ChunkSize uint32 // defaults to 0
}

const defaultChunk uint32 = 4 * 1024 * 1024

func withDefaults(o Options) Options {
	if o.ChunkSize == 0 {
		o.ChunkSize = defaultChunk
	}
	return o
}
