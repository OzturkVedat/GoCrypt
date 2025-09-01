package engine

import (
	"encoding/binary"
)

// 12B GCM nonce = 8B base || 4B chunkIndex (BE is conventional)
func makeNonce(base [8]byte, idx uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce[:8], base[:])
	binary.BigEndian.PutUint32(nonce[8:], idx)
	return nonce
}

// AAD = prefix || SHA256(headerBytes) || be32(idx)
const aadPrefix = "qforge/v1"

func aadForIndex(idx uint32, hdrDigest [32]byte) []byte {
	aad := make([]byte, 0, len(aadPrefix)+len(hdrDigest)+4)

	aad = append(aad, []byte(aadPrefix)...) // context/version
	aad = append(aad, hdrDigest[:]...)      // binds chunks to header

	var be [4]byte
	binary.BigEndian.PutUint32(be[:], idx)
	aad = append(aad, be[:]...)
	return aad
}
