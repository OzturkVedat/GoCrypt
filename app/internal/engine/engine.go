package engine

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"

	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	mycrypto "gocrypt/internal/crypto"
	"gocrypt/internal/header"
)

const MaxAcceptedChunk = 16 * 1024 * 1024 // cap what you accept from file headers

func EncryptFile(opt Options) error {
	opt = withDefaults(opt)

	src, err := os.Open(opt.InPath)
	if err != nil {
		return err
	}
	defer src.Close()

	tmp := opt.OutPath + ".part"
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer dst.Close()

	// build header
	var h header.Header
	if _, err := io.ReadFull(rand.Reader, h.Salt[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(rand.Reader, h.NonceBase[:]); err != nil {
		return err
	}
	h.ChunkSize = opt.ChunkSize

	// derive key and AEAD
	key := mycrypto.DeriveKey(opt.Pass, h.Salt[:], mycrypto.DefaultArgon2)
	aead, err := mycrypto.NewAESGCM(key)
	if err != nil {
		return err
	}

	// hmac for keyed integrity check
	hmacKey := sha256.Sum256(append([]byte("hmac"), key...))
	mac := hmac.New(sha256.New, hmacKey[:])

	// write header and keep exact bytes for digest
	headerBytes, err := header.WriteRaw(dst, h)
	if err != nil {
		return err
	}
	hdrDigest := sha256.Sum256(headerBytes)

	mac.Write(headerBytes)

	// stream encrypt chunks
	buf := make([]byte, h.ChunkSize)
	lenBuf := make([]byte, 4)
	var idx uint32

	writeChunk := func(pt []byte, idx uint32) error {
		nonce := makeNonce(h.NonceBase, idx)
		aad := aadForIndex(idx, hdrDigest)
		ct := aead.Seal(nil, nonce, pt, aad)

		binary.LittleEndian.PutUint32(lenBuf, uint32(len(ct)))
		if _, err := dst.Write(lenBuf); err != nil {
			return fmt.Errorf("write len: %w", err)
		}
		if _, err := dst.Write(ct); err != nil {
			return fmt.Errorf("write ct: %w", err)
		}

		// update mac
		mac.Write(lenBuf)
		mac.Write(ct)
		return nil
	}

	for {
		n, rerr := io.ReadFull(src, buf)
		switch rerr {
		case nil:
			if err := writeChunk(buf[:n], idx); err != nil {
				return err
			}
			idx++
		case io.ErrUnexpectedEOF, io.EOF:
			if n > 0 {
				if err := writeChunk(buf[:n], idx); err != nil {
					return err
				}
				idx++
			}
			goto DONE
		default:
			return rerr
		}

		if idx == math.MaxUint32 {
			// Would wrap the counter on next chunk: abort to avoid nonce reuse
			break
		}
	}

DONE:
	tag := mac.Sum(nil) // finalizing mac, appending to EOF
	if _, err := dst.Write(tag); err != nil {
		return fmt.Errorf("write final mac: %w", err)
	}
	if err := dst.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, opt.OutPath)
}

func DecryptFile(opt Options) error {
	opt = withDefaults(opt)

	src, err := os.Open(opt.InPath)
	if err != nil {
		return err
	}
	defer src.Close()

	// read header and keep exact bytes for digest
	h, headerBytes, err := header.ReadRaw(src)
	if err != nil {
		return err
	}

	// header sanity
	if h.ChunkSize == 0 || h.ChunkSize > MaxAcceptedChunk {
		return errors.New("header: chunk size out of range")
	}

	key := mycrypto.DeriveKey(opt.Pass, h.Salt[:], mycrypto.DefaultArgon2)
	aead, err := mycrypto.NewAESGCM(key)
	if err != nil {
		return err
	}

	// setup hmac
	hmacKey := sha256.Sum256(append([]byte("hmac"), key...))
	mac := hmac.New(sha256.New, hmacKey[:])
	mac.Write(headerBytes)

	dst, err := os.OpenFile(opt.OutPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer dst.Close()

	hdrDigest := sha256.Sum256(headerBytes)

	var idx uint32
	lenBuf := make([]byte, 4)
	maxCt := int(h.ChunkSize) + aead.Overhead()

	// get total size to learn where hmac tag starts
	stat, err := src.Stat()
	if err != nil {
		return err
	}
	fileSize := stat.Size()
	tagSize := sha256.Size
	dataEnd := fileSize - int64(tagSize)

	for {
		// stop before the final mac
		if offSet, _ := src.Seek(0, io.SeekCurrent); offSet >= dataEnd {
			break
		}

		_, rerr := io.ReadFull(src, lenBuf)
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fmt.Errorf("read chunk length: %w", rerr)
		}
		mac.Write(lenBuf) // update mac

		l := binary.LittleEndian.Uint32(lenBuf)
		if l == 0 || int(l) < aead.Overhead() || int(l) > maxCt {
			return errors.New("bad chunk length")
		}

		ct := make([]byte, l)
		if _, err := io.ReadFull(src, ct); err != nil {
			return fmt.Errorf("read ciphertext: %w", err)
		}
		mac.Write(ct) // update

		pt, err := aead.Open(nil, makeNonce(h.NonceBase, idx), ct, aadForIndex(idx, hdrDigest))
		if err != nil {
			return fmt.Errorf("decrypt chunk %d: %w", idx, err)
		}
		if _, err := dst.Write(pt); err != nil {
			return fmt.Errorf("write plaintext: %w", err)
		}

		idx++
	}

	storedTag := make([]byte, tagSize)
	if _, err := io.ReadFull(src, storedTag); err != nil {
		return fmt.Errorf("read final mac: %w", err)
	}

	if !hmac.Equal(storedTag, mac.Sum(nil)) {
		return errors.New("verification failed: file may be corrupted or tampered")
	}

	return nil
}
