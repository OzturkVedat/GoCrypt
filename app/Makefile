.PHONY: build file encrypt decrypt run clean

build:
	go build -o gocrypt ./cmd/gocrypt

file:
	dd if=/dev/zero of=big.bin bs=1M count=2048 status=progress

encrypt:
	@set -e
	@./gocrypt -mode encrypt -in big.bin
	@ls -lh big.bin.enc

decrypt:
	@set -e
	@mv big.bin big.bin.orig || true
	@./gocrypt -mode decrypt -in big.bin.enc
	@ls -lh big.bin

run: encrypt decrypt
	@cmp -s big.bin.orig big.bin && echo OK || (echo FAIL; exit 1)

clean:
	rm -f gocrypt big.bin.orig big.bin.enc
