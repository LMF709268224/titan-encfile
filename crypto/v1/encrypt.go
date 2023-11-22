package v1

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/scrypt"
)

// randBytes returns random bytes in a byte slice of size.
func randBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return b, err
}

// keys derives AES and HMAC keys from a password and salt.
func keys(pass, salt []byte, iterations int) (aesKey, hmacKey []byte, err error) {
	key, err := scrypt.Key(pass, salt, iterations, 8, 1, keySize)
	if err != nil {
		return nil, nil, err
	}

	aesKey = append(aesKey, key[:aesKeySize]...)
	hmacKey = append(hmacKey, key[aesKeySize:keySize]...)

	return aesKey, hmacKey, nil
}

// NewEncryptReader returns an io.Reader wrapping the provided io.Reader.
// It uses a user provided password and a random salt to derive keys.
// If the key is provided interactively, it should be verified since there
// is no recovery.
func NewEncryptReader(r io.Reader, pass, cryptPass, fileExt []byte) (io.Reader, error) {
	salt, err := randBytes(saltSize)
	if err != nil {
		return nil, err
	}

	return newEncryptReader(r, pass, cryptPass, salt, fileExt, scryptIterations)
}

// Make sure we implement io.ReadWriter.
var _ io.ReadWriter = &hashReadWriter{}

// hashReadWriter hashes on write and on read finalizes the hash and returns it.
// Writes after a Read will return an error.
type hashReadWriter struct {
	hash hash.Hash
	done bool
	sum  io.Reader
}

// Write implements io.Writer
func (h *hashReadWriter) Write(p []byte) (int, error) {
	if h.done {
		return 0, errors.New("writing to hashReadWriter after read is not allowed")
	}

	return h.hash.Write(p)
}

// Read implements io.Reader.
func (h *hashReadWriter) Read(p []byte) (int, error) {
	if !h.done {
		h.done = true
		h.sum = bytes.NewReader(h.hash.Sum(nil))
	}

	return h.sum.Read(p)
}

// encInt32 will encode a int32 in to a byte slice.
func encInt32(i int32) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, i); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// decInt32 will read an int32 from a reader and return the byte slice and the int32.
func decInt32(r io.Reader) (b []byte, i int32, err error) {
	buf := new(bytes.Buffer)
	tr := io.TeeReader(r, buf)
	err = binary.Read(tr, binary.LittleEndian, &i)

	return buf.Bytes(), i, err
}

// newEncryptReader returns a encryptReader wrapping an io.Reader.
// It uses a user provided password and the provided salt iterated the
// provided number of times to derive keys.
func newEncryptReader(r io.Reader, pass, cryptPass, salt, fileExt []byte, iterations int32) (io.Reader, error) {
	itersAsBytes, err := encInt32(iterations)
	if err != nil {
		return nil, err
	}

	aesKey, hmacKey, err := keys(pass, salt, int(iterations))
	if err != nil {
		return nil, err
	}

	iv, err := randBytes(blockSize)
	if err != nil {
		return nil, err
	}

	fmt.Println("fileExt size :", len(fileExt))

	cryptPass2 := padToSpecifiedBytes(cryptPass, passwordSize)
	fileExt2 := padToSpecifiedBytes(fileExt, fileExtSize)

	var header []byte
	header = append(header, itersAsBytes...)
	header = append(header, salt...)
	header = append(header, cryptPass2...)
	header = append(header, fileExt2...)
	header = append(header, iv...)
	return encrypter(r, aesKey, hmacKey, iv, header)
}

// encrypter returns the encrypted reader passed on the keys and IV provided.
func encrypter(r io.Reader, aesKey, hmacKey, iv, header []byte) (io.Reader, error) {
	b, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	h := hmac.New(hashFunc, hmacKey)
	hr := &hashReadWriter{hash: h}
	sr := &cipher.StreamReader{R: r, S: cipher.NewCTR(b, iv)}
	return io.MultiReader(io.TeeReader(io.MultiReader(bytes.NewReader(header), sr), hr), hr), nil
}
