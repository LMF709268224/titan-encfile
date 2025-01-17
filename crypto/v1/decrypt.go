package v1

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"errors"
	"io"
)

// decodeHeader decodes the header of the reader.
// It returns the keys, IV, and original header using the password and iterations in the reader.
func decodeHeader(r io.Reader, pass []byte, decryptPassFunc func([]byte) ([]byte, error)) (aesKey, hmacKey, iv, header, fileExt []byte, err error) {
	itersAsBytes, iterations, err := decInt32(r)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	salt := make([]byte, saltSize)
	_, err = io.ReadFull(r, salt)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	cryptPass := make([]byte, passwordSize)
	_, err = io.ReadFull(r, cryptPass)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	fileExt = make([]byte, fileExtSize)
	_, err = io.ReadFull(r, fileExt)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	iv = make([]byte, blockSize)
	_, err = io.ReadFull(r, iv)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	if len(pass) <= 0 {
		if decryptPassFunc == nil {
			return nil, nil, nil, nil, nil, errors.New("pass and decryptPassFunc cannot be empty at the same time")
		}

		restored := restoreOriginalBytes(cryptPass)

		pass, err = decryptPassFunc(restored)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
	}

	aesKey, hmacKey, err = keys(pass, salt, int(iterations))
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	fileExt2 := restoreOriginalBytes(fileExt)

	header = append(header, itersAsBytes...)
	header = append(header, salt...)
	header = append(header, cryptPass...)
	header = append(header, fileExt...)
	header = append(header, iv...)
	return aesKey, hmacKey, iv, header, fileExt2, err
}

// NewDecryptReader creates an io.ReadCloser wrapping an io.Reader.
// It has to read the entire io.Reader to disk using a temp file so that it can
// hash the contents to verify that it is safe to decrypt.
// If the file is athenticated, the DecryptReader will be returned and
// the resulting bytes will be the plaintext.
func NewDecryptReader(r io.ReadSeeker, pass []byte, decryptPassFunc func([]byte) ([]byte, error)) (io.Reader, []byte, error) {
	mac := make([]byte, hmacSize)
	aesKey, hmacKey, iv, header, fileExt, err := decodeHeader(r, pass, decryptPassFunc)
	h := hmac.New(hashFunc, hmacKey)
	h.Write(header)
	if err != nil {
		return nil, nil, err
	}

	headerPos, err := r.Seek(int64(0), io.SeekCurrent)
	if err != nil {
		return nil, nil, err
	}

	var bodyCounter int64 = 0
	w := h
	buf := bufio.NewReaderSize(r, _16KB)
	for {
		b, err := buf.Peek(_16KB)
		if err != nil && err != io.EOF {
			return nil, nil, err
		}

		if err == io.EOF {
			left := buf.Buffered()
			if left < hmacSize {
				return nil, nil, ErrDecrypt
			}
			copy(mac, b[left-hmacSize:left])
			_, err = io.CopyN(w, buf, int64(left-hmacSize))
			if err != nil {
				return nil, nil, err
			}

			bodyCounter = bodyCounter + int64(left-hmacSize)
			break
		}

		_, err = io.CopyN(w, buf, _16KB-hmacSize)
		if err != nil {
			return nil, nil, err
		}
		bodyCounter = bodyCounter + int64(_16KB-hmacSize)
	}

	if !hmac.Equal(mac, h.Sum(nil)) {
		return nil, nil, ErrDecrypt
	}

	b, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, err
	}

	_, err = r.Seek(headerPos, io.SeekStart)
	if err != nil {
		return nil, nil, err
	}

	dst, err := newBodyReader(r, bodyCounter)
	if err != nil {
		return nil, nil, err
	}

	sReader := &cipher.StreamReader{R: dst, S: cipher.NewCTR(b, iv)}
	return sReader, fileExt, nil
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
