package v1

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"io"
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

// NewDecryptReader creates an io.ReadCloser wrapping an io.Reader.
// It has to read the entire io.Reader to disk using a temp file so that it can
// hash the contents to verify that it is safe to decrypt.
// If the file is athenticated, the DecryptReader will be returned and
// the resulting bytes will be the plaintext.
func NewDecryptReader(r io.ReadSeeker, pass []byte) (io.Reader, error) {
	mac := make([]byte, hmacSize)
	aesKey, hmacKey, iv, header, err := decodeHeader(r, pass)
	h := hmac.New(hashFunc, hmacKey)
	h.Write(header)
	if err != nil {
		return nil, err
	}

	headerPos, err := r.Seek(int64(0), io.SeekCurrent)
	if err != nil {
		return nil, err
	}

	var bodyCounter int64 = 0
	w := h
	buf := bufio.NewReaderSize(r, _16KB)
	for {
		b, err := buf.Peek(_16KB)
		if err != nil && err != io.EOF {
			return nil, err
		}

		if err == io.EOF {
			left := buf.Buffered()
			if left < hmacSize {
				return nil, ErrDecrypt
			}
			copy(mac, b[left-hmacSize:left])
			_, err = io.CopyN(w, buf, int64(left-hmacSize))
			if err != nil {
				return nil, err
			}

			bodyCounter = bodyCounter + int64(left-hmacSize)
			break
		}

		_, err = io.CopyN(w, buf, _16KB-hmacSize)
		if err != nil {
			return nil, err
		}
		bodyCounter = bodyCounter + int64(_16KB-hmacSize)
	}

	if !hmac.Equal(mac, h.Sum(nil)) {
		return nil, ErrDecrypt
	}

	b, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	_, err = r.Seek(headerPos, io.SeekStart)
	if err != nil {
		return nil, err
	}

	dst, err := newBodyReader(r, bodyCounter)
	if err != nil {
		return nil, err
	}

	sReader := &cipher.StreamReader{R: dst, S: cipher.NewCTR(b, iv)}
	return sReader, nil
}

type bodyReader struct {
	r               io.ReadSeeker
	totalBodyLength int64
	counter         int64
}

func newBodyReader(r io.ReadSeeker, totalBodyLength int64) (*bodyReader, error) {
	return &bodyReader{
		r:               r,
		totalBodyLength: totalBodyLength,
		counter:         0,
	}, nil
}

// Read implements io.Reader.
func (b *bodyReader) Read(dst []byte) (int, error) {
	left := b.totalBodyLength - b.counter
	if left == 0 {
		return 0, io.EOF
	}

	if left < int64(len(dst)) {
		dst = dst[:left]
	}

	n, err := b.r.Read(dst)
	b.counter = b.counter + int64(n)
	return n, err
}
