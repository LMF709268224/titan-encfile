package storage

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

const (
	pKey       = "3c3633bfaa3f8cfc2df9169d763eda6a8fb06d632e553f969f9dd2edd64dd11b"
	locatorURL = "https://120.79.221.36:5000/rpc/v0"
	apiKey     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBbGxvdyI6WyJ1c2VyIl0sIklEIjoiMHhlYjU0OWYwYjk4ODdmNDE1MGRiZDNiZDBhMjU3ZDk5ZDVlMzE2ZGJhIiwiTm9kZUlEIjoiIiwiRXh0ZW5kIjoiIn0.16n87W0DvAZp60JSRHHNbo-DLU_Tycp-Av5mrnpsHVI"
)

func encryptData(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decryptData(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func encryptFile(input, password string) (string, error) {
	content, err := os.ReadFile(input)
	if err != nil {
		fmt.Println("input ReadFile :", err.Error())
		return "", err
	}

	// Encrypt file
	encrypted, err := encryptData([]byte(password), content)
	if err != nil {
		fmt.Println("content encrypt :", err.Error())
		return "", err
	}
	fileName := input + "new"
	os.WriteFile(fileName, encrypted, 0o644)

	return fileName, nil
}

func decryptFile(input, password string) (string, error) {
	content, err := os.ReadFile(input)
	if err != nil {
		fmt.Println("input ReadFile :", err.Error())
		return "", err
	}

	// Decrypt file
	decrypted, err := decryptData([]byte(password), content)
	if err != nil {
		fmt.Println("decryptData :", err.Error())
		return "", err
	}

	fileName := input + "new"
	os.WriteFile(fileName, decrypted, 0o644)

	return fileName, nil
}

func encryptPassword(password, pKey string) (string, error) {
	privateKeyECDSA, err := crypto.HexToECDSA(pKey)
	if err != nil {
		return "", err
	}

	// encrypt
	publicKeyECDSA := &privateKeyECDSA.PublicKey
	publicKey := ecies.ImportECDSAPublic(publicKeyECDSA)
	encrypted, err := ecies.Encrypt(rand.Reader, publicKey, []byte(password), nil, nil)
	if err != nil {
		return "", err
	}

	encryptedHex := hex.EncodeToString(encrypted)

	return encryptedHex, nil
}

func decryptPassword(passwordHex, pKey string) (string, error) {
	privateKeyECDSA, err := crypto.HexToECDSA(pKey)
	if err != nil {
		return "", err
	}

	encryptedBytes, _ := hex.DecodeString(passwordHex)

	// decrypt
	privateKey := ecies.ImportECDSA(privateKeyECDSA)
	decrypted, err := privateKey.Decrypt(encryptedBytes, nil, nil)
	if err != nil {
		return "", err
	}

	return string(decrypted), err
}

func IntToBytes(n int) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(n))
	return buf
}

func BytesToInt(buf []byte) int {
	return int(binary.BigEndian.Uint32(buf))
}

func IntToBytes2(n int) []byte {
	data := int64(n)
	bytebuf := bytes.NewBuffer([]byte{})
	binary.Write(bytebuf, binary.BigEndian, data)
	return bytebuf.Bytes()
}

func BytesToInt2(bys []byte) int {
	bytebuff := bytes.NewBuffer(bys)
	var data int64
	binary.Read(bytebuff, binary.BigEndian, &data)
	return int(data)
}

func TestLen(t *testing.T) {
	i := 2
	is := IntToBytes2(i)
	fmt.Println(is)
	ii := BytesToInt2(is)
	fmt.Println(ii, " len:", len(is))
}

func TestX(t *testing.T) {
	message := "095"

	privateKeyECDSA, err := crypto.HexToECDSA(pKey)
	if err != nil {
		log.Fatal(err)
	}
	// 将消息加密
	publicKeyECDSA := &privateKeyECDSA.PublicKey
	publicKey := ecies.ImportECDSAPublic(publicKeyECDSA)
	encrypted, err := ecies.Encrypt(rand.Reader, publicKey, []byte(message), nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	// 将加密后的消息以16进制字符串形式打印出来
	encryptedHex := hex.EncodeToString(encrypted)
	fmt.Printf("Encrypted message: %s\n", encryptedHex)

	encryptedBytes, _ := hex.DecodeString(encryptedHex)

	privateKeyECDSA2, err := crypto.HexToECDSA(pKey)
	if err != nil {
		log.Fatal(err)
	}

	// 解密消息
	privateKey := ecies.ImportECDSA(privateKeyECDSA2)
	decrypted, err := privateKey.Decrypt(encryptedBytes, nil, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Decrypted message: %s\n", string(decrypted))
}

func TestEncrypt(t *testing.T) {
	passwordHex := "04493ac76f54b642f079d0a9936fdc50430cebb2405e71e596a44d0e70ca8bea68acd4b539eedcce0dc19f50aeff65ae5f0097cfb5b593a7960b100b4ab3cd27d49b8b19c848673c6331477552b3631cd68bcfee8250958b743db725522097440cd266b13193a3adc428b6f7c216d79b10151b45e658503113281407fe42c49fdf"
	input := "./README.mdnew"

	password, err := decryptPassword(passwordHex, pKey)
	if err != nil {
		fmt.Printf("decryptPassword : %s\n", err.Error())
		return
	}

	fmt.Printf("Decrypted message: %s\n", password)

	_, err = encryptFile(input, password)
	if err != nil {
		fmt.Printf("decryptFile : %s\n", err.Error())
	}
}

func TestDecrypt(t *testing.T) {
	input := "./client.zip"
	password := "1234567890000001"

	_, err := decryptFile(input, password)
	if err != nil {
		fmt.Printf("decryptFile : %s\n", err.Error())
	}
}

func TestCreateAsset(t *testing.T) {
	storage, close, err := NewStorage(locatorURL, apiKey)
	if err != nil {
		t.Fatal("NewStorage error ", err)
	}
	defer close()

	progress := func(doneSize int64, totalSize int64) {
		t.Logf("upload %d of %d", doneSize, totalSize)
	}

	password := "1234567890000001"
	input := "./README.md"

	filePath, err := encryptFile(input, password)
	if err != nil {
		t.Fatal("encryptFile error ", err)
	}

	ps, err := encryptPassword(password, pKey)
	if err != nil {
		t.Fatal("encryptPassword error ", err)
	}

	visitFile := func(fp string, fi os.DirEntry, err error) error {
		// Check for and handle errors
		if err != nil {
			fmt.Println(err) // Can be used to handle errors (e.g., permission denied)
			return nil
		}
		if fi.IsDir() {
			return nil
		} else {
			// This is a file, you can perform file-specific operations here
			// if strings.HasSuffix(fp, ".go") {
			path, err := filepath.Abs(fp)
			if err != nil {
				t.Fatal(err)
			}
			_, err = storage.UploadFilesWithPath(context.Background(), path, progress, ps)
			if err != nil {
				t.Log("upload file failed ", err.Error())
				return nil
			}

			t.Logf("totalSize %s success", fp)
			// }
		}
		return nil
	}

	err = filepath.WalkDir(filePath, visitFile)
	if err != nil {
		t.Fatal("WalkDir ", err)
	}
}

// var decodeFile = &cli.Command{
// 	Name:  "decode",
// 	Usage: "decode file",
// 	Flags: []cli.Flag{
// 		&cli.StringFlag{
// 			Name:     "filename",
// 			Usage:    "file name (./example/example.exe)",
// 			Required: true,
// 		},
// 	},

// 	Action: func(cctx *cli.Context) error {
// 		// _, closer, err := GetSchedulerAPI(cctx, "")
// 		// if err != nil {
// 		// 	return err
// 		// }
// 		// defer closer()

// 		filename := cctx.String("filename")
// 		pKey := cctx.String("private-key")

// 		// TODO from titan
// 		password := cctx.String("password")

// 		fmt.Println("password:", password)

// 		privateKey, err := crypto.HexToECDSA(pKey)
// 		if err != nil {
// 			return err
// 		}

// 		// 私钥导出为字节
// 		privKeyBytes := crypto.FromECDSA(privateKey)
// 		// 得到公钥并导出为字节
// 		publicKey := privateKey.Public()
// 		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
// 		if !ok {
// 			return errors.New("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
// 		}
// 		pubKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

// 		pubKey, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
// 		if err != nil {
// 			return err
// 		}
// 		encryptedStr, err := btcec.Encrypt(pubKey, []byte(password))
// 		if err != nil {
// 			return err
// 		}

// // 字符串解码回[]byte
// decoded, err := hex.DecodeString(password)
// if err != nil {
// 	log.Fatal(err)
// }

// 		fmt.Println("password encryptedStr :", decoded)

// 		privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)
// 		decryptedStr, err := btcec.Decrypt(privKey, decoded)
// 		if err != nil {
// 			return err
// 		}

// 		fmt.Println("password decryptedStr :", string(decryptedStr))

// 		// ctx := ReqContext(cctx)
// 		encrypted, err := os.ReadFile(filename)
// 		if err != nil {
// 			fmt.Println("input ReadFile :", err.Error())
// 			return err
// 		}

// 		// Decrypt file
// 		decrypted, err := decrypt(decryptedStr, encrypted)
// 		if err != nil {
// 			fmt.Println("encrypted decrypt :", err.Error())
// 			return err
// 		}
// 		os.WriteFile("my3.sh", decrypted, 0o644)

// 		// rsp, err := schedulerAPI.CreateUserAsset(ctx, &types.AssetProperty{AssetCID: root.String(), AssetName: output})
// 		// if err != nil {
// 		// 	return err
// 		// }

// 		return nil
// 	},
// }

// var createAsset = &cli.Command{
// 	Name:  "create",
// 	Usage: "create assets of user",
// 	Flags: []cli.Flag{
// 		&cli.StringFlag{
// 			Name:     "input",
// 			Usage:    "input file name (./example/example.exe)",
// 			Required: true,
// 		},
// 		&cli.StringFlag{
// 			Name:     "output",
// 			Usage:    "output file name (./example/example.exe)",
// 			Required: true,
// 		},
// 		&cli.StringFlag{
// 			Name:     "password",
// 			Usage:    "password to lock the file",
// 			Required: true,
// 		},
// 		&cli.StringFlag{
// 			Name:     "private-key",
// 			Usage:    "eth private key",
// 			Required: true,
// 		},
// 	},

// 	Action: func(cctx *cli.Context) error {
// 		input := cctx.String("input")
// 		output := cctx.String("output")
// 		password := cctx.String("password")
// 		pKey := cctx.String("private-key")

// 		// 文件加密
// 		content, err := os.ReadFile(input)
// 		if err != nil {
// 			fmt.Println("input ReadFile :", err.Error())
// 			return err
// 		}

// 		// Encrypt file
// 		encrypted, err := encrypt([]byte(password), content)
// 		if err != nil {
// 			fmt.Println("content encrypt :", err.Error())
// 			return err
// 		}
// 		fileName := input + "new"
// 		os.WriteFile(fileName, encrypted, 0o644)

// 		// 把加密后的文件打成car
// 		root, err := carutil.CreateCar(fileName, output)
// 		if err != nil {
// 			return err
// 		}
// 		fmt.Println("cid:", root.String())

// 		// 加密password 并存到titan TODO
// 		privateKey, err := crypto.HexToECDSA(pKey)
// 		if err != nil {
// 			return err
// 		}

// 		// 得到公钥并导出为字节
// 		publicKey := privateKey.Public()
// 		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
// 		if !ok {
// 			return errors.New("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
// 		}
// 		pubKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

// 		pubKey, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
// 		if err != nil {
// 			return err
// 		}
// 		encryptedStr, err := btcec.Encrypt(pubKey, []byte(password))
// 		if err != nil {
// 			return err
// 		}

// 		// 加密后的password
// 		fmt.Println("password encryptedStr :", encryptedStr)

// 		schedulerAPI, closer, err := GetSchedulerAPI(cctx, "")
// 		if err != nil {
// 			return err
// 		}
// 		defer closer()

// 		ctx := ReqContext(cctx)
// 		rsp, err := schedulerAPI.CreateUserAsset(ctx, &types.AssetProperty{AssetCID: root.String(), AssetName: input, Password: string(encryptedStr)})
// 		if err != nil {
// 			return err
// 		}

// 		// 上传文件

// 		return nil
// 	},
// }
