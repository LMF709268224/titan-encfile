package main

import (
	c "encfile/crypto"
	"fmt"
	"io"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli/v2"
)

var (
	GITCOMMIT = ""
	VERSION   = "1.0"
)

func encrypt(ctx *cli.Context) error {
	infile := ctx.String("in")
	outfile := ctx.String("out")
	password := ctx.String("password")

	if infile == "" {
		return fmt.Errorf("no input file specified")
	}

	if outfile == "" {
		return fmt.Errorf("no output file specified")
	}

	if len(password) < 6 {
		return fmt.Errorf("password length should >= 6")
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

	r, err := c.NewEncrypter(in, []byte(password))
	if err != nil {
		return fmt.Errorf("NewEncrypter failed:%v", err)
	}

	cx, err := io.Copy(out, r)
	if err != nil {
		return fmt.Errorf("io.Copy failed:%v", err)
	}

	log.Infof("encrypt file %s, write:%d bytes to %s", infile, cx, outfile)
	return nil
}

func decrypt(ctx *cli.Context) error {
	infile := ctx.String("in")
	outfile := ctx.String("out")
	password := ctx.String("password")

	if infile == "" {
		return fmt.Errorf("no input file specified")
	}

	if outfile == "" {
		return fmt.Errorf("no output file specified")
	}

	if len(password) < 6 {
		return fmt.Errorf("password length should >= 6")
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

	r, err := c.NewDecrypter(in, []byte(password))
	if err != nil {
		return fmt.Errorf("NewEncrypter failed:%v", err)
	}

	cx, err := io.Copy(out, r)
	if err != nil {
		return fmt.Errorf("io.Copy failed:%v", err)
	}

	log.Infof("decrypt file %s, write:%d bytes to %s", infile, cx, outfile)
	return nil
}

func main() {
	cli.VersionPrinter = func(cCtx *cli.Context) {
		fmt.Printf("version=%s commit=%s\n", cCtx.App.Version, GITCOMMIT)
	}

	app := &cli.App{
		Name:    "encfile",
		Usage:   "encrypt or decrypt file",
		Version: VERSION,
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
				Required: true,
				EnvVars:  []string{"ENCFILE_PASSWORD"},
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
