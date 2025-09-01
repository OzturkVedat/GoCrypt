package engine

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"

	"context"
	"sync"
	"sync/atomic"

	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	mycrypto "gocrypt/internal/crypto"
	"gocrypt/internal/header"
)

const MaxAcceptedChunk = 16 * 1024 * 1024 // cap what you accept from file headers

func EncryptFile(opt Options) (retErr error) {
	opt = AutoAdjust(opt)
	log.Printf("Encrypt opts: workers=%d chunk=%d", opt.Workers, opt.ChunkSize)

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
	defer func() {
		_ = dst.Close()
		if retErr != nil {
			_ = os.Remove(tmp)
		}
	}()

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

	// hmac
	hmacKey := sha256.Sum256(append([]byte("hmac"), key...))
	mac := hmac.New(sha256.New, hmacKey[:])

	// header
	headerBytes, err := header.WriteRaw(dst, h)
	if err != nil {
		return err
	}
	hdrDigest := sha256.Sum256(headerBytes)
	mac.Write(headerBytes)

	type job struct {
		idx    uint32
		pt     []byte
		offset int64 // start of this chunk (length prefix goes here)
		ctLen  int   // n + aead.Overhead()
	}
	type res struct {
		idx   uint32
		ct    []byte
		ctLen int
		err   error
	}

	jobs := make(chan job, opt.Workers*2)
	results := make(chan res, opt.Workers*2)

	// workers: Seal and WriteAt(len||ct)
	var wg sync.WaitGroup
	for w := 0; w < opt.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for jb := range jobs {
				nonce := makeNonce(h.NonceBase, jb.idx)
				aad := aadForIndex(jb.idx, hdrDigest)
				ct := aead.Seal(nil, nonce, jb.pt, aad)

				// write 4B length prefix + ciphertext
				lenBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(lenBuf, uint32(len(ct)))
				if _, err := dst.WriteAt(lenBuf, jb.offset); err != nil {
					results <- res{idx: jb.idx, err: fmt.Errorf("write len: %w", err)}
					continue
				}
				if _, err := dst.WriteAt(ct, jb.offset+4); err != nil {
					results <- res{idx: jb.idx, err: fmt.Errorf("write ct: %w", err)}
					continue
				}
				results <- res{idx: jb.idx, ct: ct, ctLen: len(ct)}
			}
		}()
	}
	// close results after workers finish
	go func() { wg.Wait(); close(results) }()

	// concurrent
	readErrCh := make(chan error, 1)
	finalOffCh := make(chan int64, 1)
	go func() {
		defer close(jobs)
		var idx uint32
		readBuf := make([]byte, h.ChunkSize)
		off := int64(len(headerBytes)) // first chunk starts right after header

		for {
			n, rerr := io.ReadFull(src, readBuf)
			if n > 0 {
				if idx == math.MaxUint32 {
					readErrCh <- fmt.Errorf("file too large: GCM nonce would wrap")
					return
				}
				pt := make([]byte, n)
				copy(pt, readBuf[:n])
				ctLen := n + aead.Overhead()

				// backpressure respected by channel buffer
				jobs <- job{idx: idx, pt: pt, offset: off, ctLen: ctLen}

				off += int64(4 + ctLen) // length prefix + ct
				idx++
			}
			if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
				finalOffCh <- off
				readErrCh <- nil
				return
			}
			if rerr != nil {
				readErrCh <- rerr
				return
			}
		}
	}()

	// mac- drain results as they arrive, keep index order
	want := uint32(0)
	pending := make(map[uint32]res)
	lenBuf := make([]byte, 4)

	flush := func(r res) {
		binary.LittleEndian.PutUint32(lenBuf, uint32(r.ctLen))
		mac.Write(lenBuf)
		mac.Write(r.ct)
	}

	for r := range results {
		if r.err != nil {
			retErr = r.err
			return retErr
		}
		pending[r.idx] = r
		for {
			pr, ok := pending[want]
			if !ok {
				break
			}
			flush(pr)
			delete(pending, want)
			want++
		}
	}

	// checking reader outcome and final offset
	if rerr := <-readErrCh; rerr != nil {
		retErr = rerr
		return retErr
	}
	off := <-finalOffCh

	// final HMAC tag at EOF
	tag := mac.Sum(nil)
	if _, err := dst.WriteAt(tag, off); err != nil {
		retErr = fmt.Errorf("write final mac: %w", err)
		return retErr
	}
	if err := dst.Close(); err != nil {
		retErr = err
		return retErr
	}
	retErr = os.Rename(tmp, opt.OutPath)
	return retErr
}

func DecryptFile(opt Options) (retErr error) {
	opt = AutoAdjust(opt)
	log.Printf("Decrypt opts: workers=%d chunk=%d", opt.Workers, opt.ChunkSize)

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
	if h.ChunkSize == 0 || h.ChunkSize > MaxAcceptedChunk {
		return errors.New("header: chunk size out of range")
	}

	key := mycrypto.DeriveKey(opt.Pass, h.Salt[:], mycrypto.DefaultArgon2)
	aead, err := mycrypto.NewAESGCM(key)
	if err != nil {
		return err
	}

	// setup hmac (header || (len||ct)*)
	hmacKey := sha256.Sum256(append([]byte("hmac"), key...))
	mac := hmac.New(sha256.New, hmacKey[:])
	mac.Write(headerBytes)
	hdrDigest := sha256.Sum256(headerBytes)

	// output temp
	tmp := opt.OutPath + ".part"
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		_ = dst.Close()
		if retErr != nil {
			_ = os.Remove(tmp)
		}
	}()

	stat, err := src.Stat()
	if err != nil {
		return err
	}
	fileSize := stat.Size()
	tagSize := sha256.Size
	dataEnd := fileSize - int64(tagSize)

	// buffered reader (fewer syscalls on win)
	br := bufio.NewReaderSize(src, int(h.ChunkSize)*2)

	type job struct {
		idx uint32
		ct  []byte
	}
	jobs := make(chan job, opt.Workers*2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	verifyCh := make(chan error, 1)

	// reader goroutine: stream (len||ct), update HMAC, enqueue jobs, pre-grow dst
	go func() {
		defer close(jobs)
		var idx uint32
		var pos int64 = int64(len(headerBytes)) // we consumed header already
		var prealloc int64                      // current preallocated size
		const stride = 1024                     // every ~1GiB if ChunkSize=1MiB
		const ahead = 1024                      // preallocate an extra ~1GiB ahead

		var lenBuf [4]byte

		for pos < dataEnd {
			if _, rerr := io.ReadFull(br, lenBuf[:]); rerr != nil {
				if rerr == io.EOF {
					break
				}
				verifyCh <- fmt.Errorf("read chunk length: %w", rerr)
				cancel()
				return
			}
			pos += 4
			mac.Write(lenBuf[:])

			l := int(binary.LittleEndian.Uint32(lenBuf[:]))
			if l == 0 || l < aead.Overhead() || l > int(h.ChunkSize)+aead.Overhead() {
				verifyCh <- errors.New("bad chunk length")
				cancel()
				return
			}

			ct := make([]byte, l)
			if _, rerr := io.ReadFull(br, ct); rerr != nil {
				verifyCh <- fmt.Errorf("read ciphertext: %w", rerr)
				cancel()
				return
			}
			pos += int64(l)
			mac.Write(ct)

			// enqueue for workers
			select {
			case jobs <- job{idx: idx, ct: ct}:
			case <-ctx.Done():
				return
			}

			// coarsely pre-grow output to reduce NTFS extend/zero-fill overhead
			// grow to (idx+ahead)*ChunkSize every 'stride' chunks
			if idx%stride == 0 {
				target := int64(idx+ahead) * int64(h.ChunkSize)
				if target > prealloc {
					_ = dst.Truncate(target) // best effort; safe to over-allocate
					prealloc = target
				}
			}

			idx++
			if idx == math.MaxUint32 {
				verifyCh <- fmt.Errorf("file too large: GCM nonce would wrap")
				cancel()
				return
			}
		}

		// final hmac
		stored := make([]byte, tagSize)
		if _, rerr := io.ReadFull(br, stored); rerr != nil {
			verifyCh <- fmt.Errorf("read final mac: %w", rerr)
			cancel()
			return
		}
		if !hmac.Equal(stored, mac.Sum(nil)) {
			verifyCh <- errors.New("verification failed: file may be corrupted or tampered")
			cancel()
			return
		}
		verifyCh <- nil
	}()

	// decrypt and WriteAt to proper offset (workers)
	var wg sync.WaitGroup
	var maxEnd int64 // track final size (largest end offset)
	var firstErr atomic.Value

	for i := 0; i < opt.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case jb, ok := <-jobs:
					if !ok {
						return
					}
					nonce := makeNonce(h.NonceBase, jb.idx)
					aad := aadForIndex(jb.idx, hdrDigest)
					pt, derr := aead.Open(nil, nonce, jb.ct, aad)
					if derr != nil {
						firstErr.Store(fmt.Errorf("decrypt chunk %d: %w", jb.idx, derr))
						cancel()
						return
					}
					offset := int64(jb.idx) * int64(h.ChunkSize)
					if _, werr := dst.WriteAt(pt, offset); werr != nil {
						firstErr.Store(fmt.Errorf("write plaintext: %w", werr))
						cancel()
						return
					}
					end := offset + int64(len(pt))
					for {
						old := atomic.LoadInt64(&maxEnd)
						if end <= old {
							break
						}
						if atomic.CompareAndSwapInt64(&maxEnd, old, end) {
							break
						}
					}
				}
			}
		}()
	}

	wg.Wait()
	if v := firstErr.Load(); v != nil {
		return v.(error)
	}

	// hmac result (reader goroutine)
	if verr := <-verifyCh; verr != nil {
		return verr
	}

	// ensure correct final size
	if err := dst.Truncate(maxEnd); err != nil {
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, opt.OutPath)
}
