package v1

import (
	"crypto/aes"
	"crypto/sha512"
	"errors"
	"hash"
	"io"
)

const (
	// The size of the HMAC sum.
	hmacSize = sha512.Size

	// The size of the HMAC key.
	hmacKeySize = 32 // 256 bits

	// The size of the random salt.
	saltSize = 32 // 256 bits

	// The size of the AES key.
	aesKeySize = 32 // 256 bits

	// The size of the AES block.
	blockSize = aes.BlockSize

	// The number of iterations to use in for key generation
	// See N value in https://godoc.org/golang.org/x/crypto/scrypt#Key
	// Must be a power of 2.
	scryptIterations int32 = 262144 // 2^18
)

const _16KB = 16 * 1024

var (
	// The underlying hash function to use for HMAC.
	hashFunc = sha512.New

	// The amount of key material we need.
	keySize = hmacKeySize + aesKeySize

	// The size of the Header.
	HeaderSize = 4 + saltSize + blockSize

	// The overhead added to the file by using this library.
	// Overhead + len(plaintext) == len(ciphertext)
	Overhead = HeaderSize + hmacSize
)

var DecryptErr = errors.New("message corrupt or incorrect password")

// Hash hashes the plaintext based on the header of the encrypted file and returns the hash Sum.
func Hash(plainTextR io.Reader, headerR io.Reader, password []byte, h hash.Hash) ([]byte, error) {
	aesKey, hmacKey, iv, eHeader, err := decodeHeader(headerR, password)
	if err != nil {
		return nil, err
	}
	encReader, err := encrypter(plainTextR, aesKey, hmacKey, iv, eHeader)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(h, encReader); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
