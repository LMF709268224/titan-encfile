package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"time"

	c "encfile/crypto"
	"encfile/version"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli/v2"
)

const (
	passwordLenMax = 14
	passwordLenMin = 6

	locatorURL = "https://120.79.221.36:5000/rpc/v0"
	apiKey     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBbGxvdyI6WyJ1c2VyIl0sIklEIjoiMHhlYjU0OWYwYjk4ODdmNDE1MGRiZDNiZDBhMjU3ZDk5ZDVlMzE2ZGJhIiwiTm9kZUlEIjoiIiwiRXh0ZW5kIjoiIn0.16n87W0DvAZp60JSRHHNbo-DLU_Tycp-Av5mrnpsHVI"
)

func encrypt(ctx *cli.Context) error {
	infile := ctx.String("in")
	outfile := ctx.String("out")
	password := ctx.String("password")

	pKey := ctx.String("key")

	if len(password) < passwordLenMin {
		return fmt.Errorf("password length should >= 6")
	}

	if len(password) > passwordLenMax {
		return fmt.Errorf("password length should <= 14")
	}

	passBytes := []byte(password)

	cryptPass, err := encryptPassword(passBytes, pKey)
	if err != nil {
		return fmt.Errorf("encryptPassword error %s", err.Error())
	}

	in, err := os.Open(infile)
	if err != nil {
		return fmt.Errorf("open input file failed:%v", err)
	}
	defer func() {
		in.Close()
	}()

	out, err := os.Create(outfile)
	if err != nil {
		return fmt.Errorf("create output file failed:%v", err)
	}
	defer func() {
		out.Close()
	}()

	start := time.Now()
	r, err := c.NewEncrypter(in, passBytes, cryptPass)
	if err != nil {
		return fmt.Errorf("NewEncrypter failed:%v", err)
	}

	cx, err := io.Copy(out, r)
	if err != nil {
		return fmt.Errorf("io.Copy failed:%v", err)
	}

	elapsed := time.Since(start)
	log.Infof("encrypt file %s, write:%d bytes to %s, time:%s", infile, cx, outfile, elapsed)
	return nil
}

func decrypt(ctx *cli.Context) error {
	infile := ctx.String("in")
	outfile := ctx.String("out")
	password := ctx.String("password")

	var passBytes []byte
	if len(password) > 0 {
		passBytes = []byte(password)
	}

	in, err := os.Open(infile)
	if err != nil {
		return fmt.Errorf("open input file failed:%v", err)
	}
	defer func() {
		in.Close()
	}()

	out, err := os.Create(outfile)
	if err != nil {
		return fmt.Errorf("create output file failed:%v", err)
	}
	defer func() {
		out.Close()
	}()

	start := time.Now()

	pKey := ctx.String("key")
	decryptPassFunc := func(cryptPass []byte) ([]byte, error) {
		privateKeyECDSA, err := crypto.HexToECDSA(pKey)
		if err != nil {
			return nil, err
		}

		// decrypt
		privateKey := ecies.ImportECDSA(privateKeyECDSA)

		return privateKey.Decrypt(cryptPass, nil, nil)
	}

	r, err := c.NewDecrypter(in, passBytes, decryptPassFunc)
	if err != nil {
		return fmt.Errorf("NewDecrypter failed:%v", err)
	}

	cx, err := io.Copy(out, r)
	if err != nil {
		return fmt.Errorf("io.Copy failed:%v", err)
	}

	elapsed := time.Since(start)
	log.Infof("decrypt file %s, write:%d bytes to %s, time:%s", infile, cx, outfile, elapsed)
	return nil
}

func main() {
	cli.VersionPrinter = func(cCtx *cli.Context) {
		fmt.Printf("version=%s commit=%s\n", cCtx.App.Version, version.GITCOMMIT)
	}

	app := &cli.App{
		Name:    "encfile",
		Usage:   "encrypt or decrypt file",
		Version: version.VERSION,
		Commands: []*cli.Command{
			{
				Name:    "encrypt",
				Aliases: []string{"e"},
				Usage:   "encrypt a file",
				Action: func(cCtx *cli.Context) error {
					return encrypt(cCtx)
				},
			},
			{
				Name:    "decrypt",
				Aliases: []string{"d"},
				Usage:   "decrypt a file",
				Action: func(cCtx *cli.Context) error {
					return decrypt(cCtx)
				},
			},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "password",
				Required: false,
				EnvVars:  []string{"ENCFILE_PASSWORD"},
			},
			&cli.StringFlag{
				Name:     "key",
				Required: false,
				EnvVars:  []string{"PRIVATE_KEY"},
			},
			&cli.StringFlag{
				Name:     "in",
				Required: true,
				EnvVars:  []string{"ENCFILE_IN"},
			},
			&cli.StringFlag{
				Name:     "out",
				Required: true,
				EnvVars:  []string{"ENCFILE_OUT"},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func encryptPassword(pass []byte, pKey string) ([]byte, error) {
	privateKeyECDSA, err := crypto.HexToECDSA(pKey)
	if err != nil {
		return nil, err
	}

	// encrypt
	publicKeyECDSA := &privateKeyECDSA.PublicKey
	publicKey := ecies.ImportECDSAPublic(publicKeyECDSA)

	return ecies.Encrypt(rand.Reader, publicKey, pass, nil, nil)
}
