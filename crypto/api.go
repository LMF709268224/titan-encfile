package crypto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	v1 "encfile/crypto/v1"
)

// Version is the version of the en/decryption library used.
type Version uint32

// decrypter is a function that creates a decrypter.
type decrypter func(io.ReadSeeker, []byte, func([]byte) ([]byte, error)) (io.Reader, []byte, error)

// encrypter is a function that creates a encrypter.
type encrypter func(io.Reader, []byte, []byte, []byte) (io.Reader, error)

// hasher is a function that returns the hash of a plaintext as if it were encrypted.
type hasher func(io.Reader, io.Reader, hash.Hash, []byte) ([]byte, error)

// These are the different versions of the en/decryption library.
const (
	V1 Version = iota
)

// PreferedVersion is the preferred version of encryption.
const PreferedVersion = V1

var (
	encrypters map[Version]encrypter
	decrypters map[Version]decrypter
	hashers    map[Version]hasher
)

// MaxHeaderSize is the maximum header size of all versions.
// This many bytes at the beginning of a file should be enough to compute
// a hash of a local file.
var MaxHeaderSize = v1.HeaderSize + 4

// Overhead is the overhead added by the preferred encryption library plus the version.
var Overhead = v1.Overhead + 4

func init() {
	decrypters = map[Version]decrypter{
		V1: v1.NewDecryptReader,
	}

	encrypters = map[Version]encrypter{
		V1: v1.NewEncryptReader,
	}
	hashers = map[Version]hasher{
		V1: v1.Hash,
	}
}

// NewEncrypter returns an encrypting reader using the PreferedVersion.
func NewEncrypter(r io.Reader, password, cryptPassword, fileExt []byte) (io.Reader, error) {
	v, err := writeVersion(PreferedVersion)
	if err != nil {
		return nil, err
	}
	encrypterFn, ok := encrypters[PreferedVersion]
	if !ok {
		return nil, fmt.Errorf("%v version could not be found", PreferedVersion)
	}
	encReader, err := encrypterFn(r, password, cryptPassword, fileExt)
	if err != nil {
		return nil, err
	}
	return io.MultiReader(bytes.NewReader(v), encReader), nil
}

// NewDecrypter returns a decrypting reader based on the version used to encrypt.
func NewDecrypter(r io.ReadSeeker, pass []byte, decryptPassFunc func([]byte) ([]byte, error)) (io.Reader, []byte, error) {
	version, err := readVersion(r)
	if err != nil {
		return nil, nil, err
	}
	decrypterFn, ok := decrypters[version]
	if !ok {
		return nil, nil, fmt.Errorf("unknown decrypter for version(%d)", version)
	}
	return decrypterFn(r, pass, decryptPassFunc)
}

// Hash will hash of plaintext based on the header of the encrypted file and returns the hash Sum.
func Hash(r io.Reader, header io.Reader, hashFunc func() hash.Hash, pass []byte) ([]byte, error) {
	h := hashFunc()
	version, err := readVersion(io.TeeReader(header, h))
	if err != nil {
		return nil, err
	}
	hasherFn, ok := hashers[version]
	if !ok {
		return nil, fmt.Errorf("unknown hasher for version(%d)", version)
	}
	return hasherFn(r, header, h, pass)
}

// writeVersion converts a Version to a []byte.
func writeVersion(i Version) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, i); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// readVersion reads and returns a Version from reader.
func readVersion(r io.Reader) (v Version, err error) {
	err = binary.Read(r, binary.LittleEndian, &v)
	return v, err
}
