package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	c "encfile/crypto"
	"encfile/storage"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	log "github.com/sirupsen/logrus"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

const (
	passwordLenMax = 70
	passwordLenMin = 6

	title = "File encrypt and decrypt"

	textInputFile     = "Drag and drop a file here"
	textUploadFile    = "Drag and drop a file here"
	textDragErrorFile = "Drag and drop file format error"
	apiKeyFile        = "Enter api key..."
	textInputPass     = "Enter password..."
	textInputKey      = "Enter private key..."

	textInputFileBtn    = "Select input file"
	textEncryptBtn      = "Encrypt"
	textDecryptBtn      = "Decrypt"
	textSelectFileBtn   = "Select upload file"
	textUploadBtn       = "Upload to titan"
	confirmDialogTTitle = "Please confirm to upload the following file"

	locatorURL = "https://120.79.221.36:5000/rpc/v0"
)

func encrypt(inFile, password, privateKey string) (string, error) {
	if password == "" {
		password = privateKey
	}

	err := checkParameters(inFile, password, privateKey, true)
	if err != nil {
		return "", err
	}

	fmt.Println("password len:", len(password))
	passBytes := []byte(password)
	fmt.Println("byte len:", len(passBytes))

	cryptPass, err := encryptPassword(passBytes, privateKey)
	if err != nil {
		return "", fmt.Errorf("encryptPassword error %s", err.Error())
	}

	in, err := os.Open(inFile)
	if err != nil {
		return "", fmt.Errorf("open input file failed:%v", err)
	}
	defer func() {
		in.Close()
	}()

	dir := filepath.Dir(inFile)
	ext := filepath.Ext(inFile)

	fileName := filepath.Base(inFile)
	baseName := fileName[0 : len(fileName)-len(ext)]

	outFile := filepath.Join(dir, fmt.Sprintf("%s_en", baseName))
	out, err := os.Create(outFile)
	if err != nil {
		return "", fmt.Errorf("create output file failed:%v", err)
	}
	defer func() {
		out.Close()
	}()

	start := time.Now()
	r, err := c.NewEncrypter(in, passBytes, cryptPass, []byte(ext))
	if err != nil {
		return "", fmt.Errorf("NewEncrypter failed:%v", err)
	}

	cx, err := io.Copy(out, r)
	if err != nil {
		return "", fmt.Errorf("io.Copy failed:%v", err)
	}

	elapsed := time.Since(start)
	log.Infof("encrypt file %s, write:%d bytes to %s, time:%s", inFile, cx, outFile, elapsed)
	return outFile, nil
}

func decrypt(inFile, password, privateKey string) (string, error) {
	err := checkParameters(inFile, password, privateKey, false)
	if err != nil {
		return "", err
	}

	var passBytes []byte
	if len(password) > 0 {
		passBytes = []byte(password)
	}

	in, err := os.Open(inFile)
	if err != nil {
		return "", fmt.Errorf("open input file failed:%v", err)
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
		return "", fmt.Errorf("NewDecrypter failed:%v", err)
	}

	ext := string(extB)

	dir := filepath.Dir(inFile)
	outFile := filepath.Join(dir, fmt.Sprintf("de_file%s", ext))

	out, err := os.Create(outFile)
	if err != nil {
		return "", fmt.Errorf("create output file failed:%v", err)
	}
	defer func() {
		out.Close()
	}()

	cx, err := io.Copy(out, r)
	if err != nil {
		return "", fmt.Errorf("io.Copy failed:%v", err)
	}

	elapsed := time.Since(start)
	log.Infof("decrypt file %s, write:%d bytes to %s, time:%s", inFile, cx, outFile, elapsed)
	return outFile, nil
}

func main() {
	fyneApp := app.New()
	window := fyneApp.NewWindow(title)

	passwordEntry := widget.NewPasswordEntry()
	privateKeyEntry := widget.NewPasswordEntry()
	resultLabel := widget.NewLabel("")
	inputFileLabel := widget.NewLabel(textInputFile)
	uploadFileLabel := widget.NewLabel(textUploadFile)
	apiKeyEntry := widget.NewEntry()
	uploadResultLabel := widget.NewLabel("")

	passwordEntry.SetPlaceHolder(textInputPass)
	privateKeyEntry.SetPlaceHolder(textInputKey)
	apiKeyEntry.SetPlaceHolder(apiKeyFile)

	encryptBtn := widget.NewButton(textEncryptBtn, func() {
		inFile := inputFileLabel.Text
		password := passwordEntry.Text
		pKey := privateKeyEntry.Text
		resultText := ""

		outFile, err := encrypt(inFile, password, pKey)
		if err != nil {
			resultText = fmt.Sprintf("error : %s", err.Error())
		} else {
			resultText = fmt.Sprintf("encrypt success ! output file: %s", outFile)
			uploadFileLabel.SetText(outFile)
		}

		resultLabel.SetText(resultText)
	})

	decryptBtn := widget.NewButton(textDecryptBtn, func() {
		inFile := inputFileLabel.Text
		password := passwordEntry.Text
		pKey := privateKeyEntry.Text
		resultText := ""

		outFile, err := decrypt(inFile, password, pKey)
		if err != nil {
			resultText = err.Error()
		} else {
			resultText = fmt.Sprintf("decrypt success ! output file: %s", outFile)
		}

		resultLabel.SetText(resultText)
	})

	uploadBtn := widget.NewButton(textUploadBtn, func() {
		apiKey := apiKeyEntry.Text
		// fmt.Println(apiKey)
		if apiKey == "" {
			uploadResultLabel.SetText("error : please enter the api key")
			return
		}

		filePath := uploadFileLabel.Text
		if filePath == textUploadFile {
			uploadResultLabel.SetText("error : please enter the upload file path")
			return
		}

		confirmDialog := dialog.NewConfirm(confirmDialogTTitle, filePath, func(result bool) {
			if result {
				fCid, err := uploadFileToTitan(locatorURL, apiKey, filePath, "1")
				if err != nil {
					uploadResultLabel.SetText(fmt.Sprintf("error : %s", err.Error()))
				} else {
					uploadResultLabel.SetText(fmt.Sprintf("cid : %s", fCid))
				}
			}
		}, window)
		confirmDialog.Show()
	})

	window.SetOnDropped(func(position fyne.Position, uris []fyne.URI) {
		log.Println("X:", position.X, " Y:", position.Y)

		if len(uris) <= 0 {
			return
		}

		var input *widget.Label
		if position.Y > 80 && position.Y < 120 {
			input = inputFileLabel
		}

		if position.Y > 280 && position.Y < 320 {
			input = uploadFileLabel
		}

		if input == nil {
			return
		}

		fille := uris[0]
		path := fille.Path()

		fileInfo, err := os.Stat(path)
		if err != nil {
			log.Println(err)
			input.SetText(textDragErrorFile)
			return
		}

		if fileInfo.IsDir() {
			input.SetText(textDragErrorFile)
		} else {
			input.SetText(path)
		}
	})

	window.SetContent(container.NewVBox(
		privateKeyEntry,
		passwordEntry,
		inputFileLabel,
		resultLabel,
		encryptBtn,
		decryptBtn,
		apiKeyEntry,
		uploadFileLabel,
		uploadResultLabel,
		uploadBtn,
	))

	window.Resize(fyne.NewSize(800, 600))
	window.ShowAndRun()
}

func checkParameters(inFile, password, pKey string, isEncrypt bool) error {
	if inFile == textInputFile {
		return fmt.Errorf("please enter the input file pash")
	}

	if isEncrypt {
		if pKey == "" {
			return fmt.Errorf("please enter the private key")
		}

		if len(password) < passwordLenMin {
			return fmt.Errorf("password length should >= %d", passwordLenMin)
		}

		if len(password) > passwordLenMax {
			return fmt.Errorf("password length should <= %d", passwordLenMax)
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

func uploadFileToTitan(locatorURL, apiKey, filePath, password string) (string, error) {
	storage, close, err := storage.NewStorage(locatorURL, apiKey)
	if err != nil {
		return "", err
	}
	defer close()

	progress := func(doneSize int64, totalSize int64) {
		fmt.Printf("upload %d of %d \n", doneSize, totalSize)
	}

	fCid := ""

	visitFile := func(fp string, fi os.DirEntry, err error) error {
		// Check for and handle errors
		if err != nil {
			fmt.Println(err) // Can be used to handle errors (e.g., permission denied)
			return nil
		}

		if fi.IsDir() {
			return nil
		}

		path, err := filepath.Abs(fp)
		if err != nil {
			return err
		}

		c, err := storage.UploadFilesWithPath(context.Background(), path, progress, password)
		if err != nil {
			return err
		}

		fCid = c.String()
		fmt.Printf("totalSize %s success \n", fp)

		return nil
	}

	return fCid, filepath.WalkDir(filePath, visitFile)
}
