package header

const Magic = "QFGE"
const Version = 1

type Header struct {
	Salt        [16]byte
	NonceBase   [8]byte
	ChunkSize   uint32
	TotalChunks uint32
}
