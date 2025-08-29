package header

import (
	"encoding/binary"
	"errors"
	"io"
)

const size = 4 + 1 + 16 + 8 + 4 // "QFGE" + ver + salt + nonceBase + chunkSize

// serializes the header into a buffer
func Marshal(h Header) []byte {
	buf := make([]byte, 0, size)

	buf = append(buf, Magic...)
	buf = append(buf, byte(Version))
	buf = append(buf, h.Salt[:]...)
	buf = append(buf, h.NonceBase[:]...)

	c := make([]byte, 4)
	binary.LittleEndian.PutUint32(c, h.ChunkSize)
	buf = append(buf, c...)
	return buf
}

// parses a header from a buffer
func Unmarshal(b []byte) (Header, error) {
	var hdr Header
	if len(b) < size {
		return hdr, errors.New("header: short buffer")
	}
	if string(b[:4]) != Magic || b[4] != byte(Version) {
		return hdr, errors.New("header: bad magic/version")
	}

	off := 5
	copy(hdr.Salt[:], b[off:off+16])
	off += 16
	copy(hdr.NonceBase[:], b[off:off+8])
	off += 8
	hdr.ChunkSize = binary.LittleEndian.Uint32(b[off : off+4])
	return hdr, nil
}

// returns the serialized header size
func Size() int { return size }

func Write(w io.Writer, h Header) error {
	_, err := w.Write(Marshal(h))
	return err
}

func Read(r io.Reader) (Header, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Header{}, err
	}
	return Unmarshal(buf)
}

// returns raw bytes (for HMAC)
func WriteRaw(w io.Writer, h Header) ([]byte, error) {
	b := Marshal(h)
	_, err := w.Write(b)
	return b, err
}

func ReadRaw(r io.Reader) (Header, []byte, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return Header{}, nil, err
	}
	h, err := Unmarshal(b)
	return h, b, err
}
