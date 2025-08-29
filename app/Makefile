.PHONY: build test clean

build:
	go build -o gocrypt ./cmd/gocrypt

pdf:
	@set -e
	@./gocrypt -mode encrypt -in example.pdf -out in.cf
	@./gocrypt -mode decrypt -in in.cf -out o_example.pdf
	@cmp -s example.pdf o_example.pdf && echo OK || (echo FAIL; exit 1)

clean:
	rm -f gocrypt in.cf o_example.pdf