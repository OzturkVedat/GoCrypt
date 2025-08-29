package crypto

import "golang.org/x/crypto/argon2"

type Argon2Params struct {
	Time    uint32 // iterations
	Memory  uint32 // KiB (e.g. 64*1024 = 64MiB)
	Threads uint8
	KeyLen  uint32 // bytes (32 for AES256)
}

func DeriveKey(pass, salt []byte, p Argon2Params) []byte {
	return argon2.IDKey(pass, salt, p.Time, p.Memory, p.Threads, p.KeyLen)
}

var DefaultArgon2 = Argon2Params{
	Time: 3, Memory: 64 * 1024, Threads: 4, KeyLen: 32,
}
