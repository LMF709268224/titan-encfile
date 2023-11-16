package v1

import (
	"bytes"
	"crypto/aes"
	"crypto/sha512"
	"encoding/binary"
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

	// The size of the password len.
	passwordLenSize = 8

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

var ErrDecrypt = errors.New("message corrupt or incorrect password")

// Hash hashes the plaintext based on the header of the encrypted file and returns the hash Sum.
func Hash(plainTextR io.Reader, headerR io.Reader, h hash.Hash, pass []byte) ([]byte, error) {
	aesKey, hmacKey, iv, eHeader, err := decodeHeader(headerR, pass, nil)
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

func intToBytes(n int) []byte {
	data := int64(n)
	bytebuf := bytes.NewBuffer([]byte{})
	binary.Write(bytebuf, binary.BigEndian, data)
	return bytebuf.Bytes()
}

func bytesToInt(bys []byte) int {
	bytebuff := bytes.NewBuffer(bys)
	var data int64
	binary.Read(bytebuff, binary.BigEndian, &data)
	return int(data)
}
