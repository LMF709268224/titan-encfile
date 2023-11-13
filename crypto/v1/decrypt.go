package v1

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"io"
	"os"

	"github.com/odeke-em/go-utils/tmpfile"
)

// decodeHeader decodes the header of the reader.
// It returns the keys, IV, and original header using the password and iterations in the reader.
func decodeHeader(r io.Reader, password []byte) (aesKey, hmacKey, iv, header []byte, err error) {
	itersAsBytes, iterations, err := decInt32(r)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	salt := make([]byte, saltSize)
	iv = make([]byte, blockSize)
	_, err = io.ReadFull(r, salt)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	_, err = io.ReadFull(r, iv)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	aesKey, hmacKey, err = keys(password, salt, int(iterations))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	header = append(header, itersAsBytes...)
	header = append(header, salt...)
	header = append(header, iv...)
	return aesKey, hmacKey, iv, header, err
}

// decryptReader wraps a io.Reader decrypting its content.
type decryptReader struct {
	tmpFile *tmpfile.TmpFile
	sReader *cipher.StreamReader
}

// NewDecryptReader creates an io.ReadCloser wrapping an io.Reader.
// It has to read the entire io.Reader to disk using a temp file so that it can
// hash the contents to verify that it is safe to decrypt.
// If the file is athenticated, the DecryptReader will be returned and
// the resulting bytes will be the plaintext.
func NewDecryptReader(r io.Reader, pass []byte) (d io.ReadCloser, err error) {
	mac := make([]byte, hmacSize)
	aesKey, hmacKey, iv, header, err := decodeHeader(r, pass)
	h := hmac.New(hashFunc, hmacKey)
	h.Write(header)
	if err != nil {
		return nil, err
	}
	dst, err := tmpfile.New(&tmpfile.Context{
		Dir:    os.TempDir(),
		Suffix: "drive-encrypted-",
	})
	if err != nil {
		return nil, err
	}
	// If there is an error, try to delete the temp file.
	defer func() {
		if err != nil {
			dst.Done()
		}
	}()
	b, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	d = &decryptReader{
		tmpFile: dst,
		sReader: &cipher.StreamReader{R: dst, S: cipher.NewCTR(b, iv)},
	}
	w := io.MultiWriter(h, dst)
	buf := bufio.NewReaderSize(r, _16KB)
	for {
		b, err := buf.Peek(_16KB)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if err == io.EOF {
			left := buf.Buffered()
			if left < hmacSize {
				return nil, DecryptErr
			}
			copy(mac, b[left-hmacSize:left])
			_, err = io.CopyN(w, buf, int64(left-hmacSize))
			if err != nil {
				return nil, err
			}
			break
		}
		_, err = io.CopyN(w, buf, _16KB-hmacSize)
		if err != nil {
			return nil, err
		}
	}
	if !hmac.Equal(mac, h.Sum(nil)) {
		return nil, DecryptErr
	}
	dst.Seek(0, 0)
	return d, nil
}

// Read implements io.Reader.
func (d *decryptReader) Read(dst []byte) (int, error) {
	return d.sReader.Read(dst)
}

// Close implements io.Closer.
func (d *decryptReader) Close() error {
	return d.tmpFile.Done()
}
