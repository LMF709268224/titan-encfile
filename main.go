package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	c "encfile/crypto"
	"encfile/version"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	log "github.com/sirupsen/logrus"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/urfave/cli/v2"
)

const (
	passwordLenMax = 14
	passwordLenMin = 6

	locatorURL = "https://120.79.221.36:5000/rpc/v0"
	apiKey     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBbGxvdyI6WyJ1c2VyIl0sIklEIjoiMHhlYjU0OWYwYjk4ODdmNDE1MGRiZDNiZDBhMjU3ZDk5ZDVlMzE2ZGJhIiwiTm9kZUlEIjoiIiwiRXh0ZW5kIjoiIn0.16n87W0DvAZp60JSRHHNbo-DLU_Tycp-Av5mrnpsHVI"
)

func encrypt(infile, password, privateKey string) error {
	// infile := ctx.String("in")
	// outfile := ctx.String("out")
	// password := ctx.String("password")
	// pKey := ctx.String("key")
	err := checkParameters(infile, password, privateKey, true)
	if err != nil {
		return err
	}

	passBytes := []byte(password)

	cryptPass, err := encryptPassword(passBytes, privateKey)
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

	dir := filepath.Dir(infile)
	ext := filepath.Ext(infile)
	fmt.Println("ext :", ext)

	fileName := filepath.Base(infile)
	baseName := fileName[0 : len(fileName)-len(ext)]
	fmt.Println("Base Name:", baseName)

	outfile := filepath.Join(dir, fmt.Sprintf("%s_en", baseName))
	out, err := os.Create(outfile)
	if err != nil {
		return fmt.Errorf("create output file failed:%v", err)
	}
	defer func() {
		out.Close()
	}()

	start := time.Now()
	r, err := c.NewEncrypter(in, passBytes, cryptPass, []byte(ext))
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

func decrypt(infile, password, privateKey string) error {
	// infile := ctx.String("in")
	// outfile := ctx.String("out")
	// password := ctx.String("password")
	// pKey := ctx.String("key")

	err := checkParameters(infile, password, privateKey, false)
	if err != nil {
		return err
	}

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

	start := time.Now()

	decryptPassFunc := func(cryptPass []byte) ([]byte, error) {
		privateKeyECDSA, err := crypto.HexToECDSA(privateKey)
		if err != nil {
			return nil, err
		}

		// decrypt
		privateKey := ecies.ImportECDSA(privateKeyECDSA)

		return privateKey.Decrypt(cryptPass, nil, nil)
	}

	r, extB, err := c.NewDecrypter(in, passBytes, decryptPassFunc)
	if err != nil {
		return fmt.Errorf("NewDecrypter failed:%v", err)
	}

	ext := string(extB)
	fmt.Println("extB :", ext)

	dir := filepath.Dir(infile)
	outfile := filepath.Join(dir, fmt.Sprintf("de_file%s", ext))

	out, err := os.Create(outfile)
	if err != nil {
		return fmt.Errorf("create output file failed:%v", err)
	}
	defer func() {
		out.Close()
	}()

	cx, err := io.Copy(out, r)
	if err != nil {
		return fmt.Errorf("io.Copy failed:%v", err)
	}

	elapsed := time.Since(start)
	log.Infof("decrypt file %s, write:%d bytes to %s, time:%s", infile, cx, outfile, elapsed)
	return nil
}

func main2() {
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
					infile := cCtx.String("in")
					// outfile := cCtx.String("out")
					password := cCtx.String("password")
					pKey := cCtx.String("key")

					return encrypt(infile, password, pKey)
				},
			},
			{
				Name:    "decrypt",
				Aliases: []string{"d"},
				Usage:   "decrypt a file",
				Action: func(cCtx *cli.Context) error {
					infile := cCtx.String("in")
					// outfile := cCtx.String("out")
					password := cCtx.String("password")
					pKey := cCtx.String("key")

					return decrypt(infile, password, pKey)
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

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("文件加解密")

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Enter password...")

	privateKeyEntry := widget.NewPasswordEntry()
	privateKeyEntry.SetPlaceHolder("Enter private key...")

	inPutEntry := widget.NewLabel("Enter input file pash...")
	// inPutEntry := widget.NewEntry()
	// inPutEntry.SetPlaceHolder("Enter input file path...(ex: D:\\abc.txt)")

	inPutBtn := widget.NewButton("select input file", func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err == nil && reader != nil {
				inPutEntry.SetText(reader.URI().Path())
			}
		}, myWindow)
		fd.Show()
	})

	// outPutEntry := widget.NewEntry()
	// outPutEntry.SetPlaceHolder("Enter output file path...(ex: D:\\abc.txt)")

	resultLabel := widget.NewLabel("")

	encryptBtn := widget.NewButton("encrypt", func() {
		infile := inPutEntry.Text
		// outfile := outPutEntry.Text
		password := passwordEntry.Text
		pKey := privateKeyEntry.Text
		resultText := "success !!!"

		err := encrypt(infile, password, pKey)
		if err != nil {
			resultText = err.Error()
		}

		resultLabel.SetText(resultText)
	})

	decryptBtn := widget.NewButton("decrypt", func() {
		infile := inPutEntry.Text
		// outfile := outPutEntry.Text
		password := passwordEntry.Text
		pKey := privateKeyEntry.Text
		resultText := "success !!!"

		err := decrypt(infile, password, pKey)
		if err != nil {
			resultText = err.Error()
		}

		resultLabel.SetText(resultText)
	})

	myWindow.SetContent(container.NewVBox(
		privateKeyEntry,
		passwordEntry,
		inPutEntry,
		inPutBtn,
		// outPutEntry,
		resultLabel,
		encryptBtn,
		decryptBtn,
	))

	myWindow.Resize(fyne.NewSize(600, 400))
	myWindow.ShowAndRun()
}

func checkParameters(infile, password, pKey string, isEncrypt bool) error {
	if infile == "" {
		return fmt.Errorf("please enter the input file pash")
	}

	// if outfile == "" {
	// 	return fmt.Errorf("please enter the output file pash")
	// }

	if isEncrypt {
		if pKey == "" {
			return fmt.Errorf("please enter the private key")
		}

		if len(password) < passwordLenMin {
			return fmt.Errorf("password length should >= 6")
		}

		if len(password) > passwordLenMax {
			return fmt.Errorf("password length should <= 14")
		}

		return nil
	}

	if pKey == "" && password == "" {
		return fmt.Errorf("password and private key cannot be empty at the same time")
	}

	return nil
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
