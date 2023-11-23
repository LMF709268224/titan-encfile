package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"encfile/storage/client"

	"github.com/ipfs/go-cid"
)

type FileType string

const (
	FileTypeFile   FileType = "file"
	FileTypeFolder FileType = "folder"
	timeout                 = 30 * time.Second
)

type (
	storageClose func()
	ProgressFunc func(doneSize int64, totalSize int64)
)

type Storage interface {
	// UploadFilesWithPath the file path can be the absolute path of a single file or a directory
	UploadFilesWithPath(ctx context.Context, filePath string, progress ProgressFunc, password string) (cid.Cid, error)
}

type storage struct {
	schedulerAPI client.Scheduler
	httpClient   *http.Client
	candidateID  string
}

func NewStorage(locatorURL, apiKey string) (Storage, storageClose, error) {
	udpPacketConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, nil, fmt.Errorf("ListenPacket %w", err)
	}

	// use http3 client
	httpClient, err := client.NewHTTP3Client(udpPacketConn, true, "")
	if err != nil {
		return nil, nil, fmt.Errorf("NewHTTP3Client %w", err)
	}

	locatorAPI := client.NewLocator(locatorURL, nil, client.HTTPClientOption(httpClient))
	schedulerURL, err := locatorAPI.GetSchedulerWithAPIKey(context.Background(), apiKey)
	if err != nil {
		return nil, nil, fmt.Errorf("GetSchedulerWithAPIKey %w", err)
	}

	headers := http.Header{}
	headers.Add("Authorization", "Bearer "+apiKey)

	schedulerAPI := client.NewScheduler(schedulerURL, headers, client.HTTPClientOption(httpClient))
	close := func() {
		udpPacketConn.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	candidates, err := schedulerAPI.GetCandidateIPs(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("GetCandidateIPs %w", err)
	}

	fastNodes := getFastNode(candidates)
	if len(fastNodes) == 0 {
		return nil, nil, fmt.Errorf("can not get any candidate node")
	}

	return &storage{schedulerAPI: schedulerAPI, httpClient: httpClient, candidateID: fastNodes[0].NodeID}, close, nil
}

// The file path can be a single file or a directory
func (s *storage) UploadFilesWithPath(ctx context.Context, filePath string, progress ProgressFunc, password string) (cid.Cid, error) {
	// delete template file if exist
	fileName := filepath.Base(filePath)
	tempFile := path.Join(os.TempDir(), fileName)
	if _, err := os.Stat(tempFile); err == nil {
		os.Remove(tempFile)
	}

	root, err := createCar(filePath, tempFile)
	if err != nil {
		return cid.Cid{}, err
	}

	carFile, err := os.Open(tempFile)
	if err != nil {
		return cid.Cid{}, err
	}

	defer func() {
		if err = carFile.Close(); err != nil {
			fmt.Println("close car file error ", err.Error())
		}

		if err = os.Remove(tempFile); err != nil {
			fmt.Println("delete temporary car file error ", err.Error())
		}
	}()

	fileInfo, err := carFile.Stat()
	if err != nil {
		return cid.Cid{}, err
	}

	fileType, err := getFileType(filePath)
	if err != nil {
		return cid.Cid{}, err
	}

	assetProperty := &client.AssetProperty{
		AssetCID:  root.String(),
		AssetName: fileName,
		AssetSize: fileInfo.Size(),
		AssetType: fileType,
		NodeID:    s.candidateID,
		Password:  password,
	}
	rsp, err := s.schedulerAPI.CreateUserAsset(ctx, assetProperty)
	if err != nil {
		return cid.Cid{}, fmt.Errorf("CreateUserAsset error %w", err)
	}

	if rsp.AlreadyExists {
		return cid.Cid{}, fmt.Errorf("asset %s already exist", root.String())
	}

	err = s.uploadFileWithForm(ctx, carFile, fileName, rsp.UploadURL, rsp.Token, progress)
	if err != nil {
		if delErr := s.schedulerAPI.DeleteUserAsset(ctx, root.String()); delErr != nil {
			return cid.Cid{}, fmt.Errorf("uploadFileWithForm failed %s, delete error %s", err.Error(), delErr.Error())
		}
		return cid.Cid{}, fmt.Errorf("uploadFileWithForm error %s, delete it from titan", err.Error())
	}

	return root, nil
}

func (s *storage) uploadFileWithForm(ctx context.Context, r io.Reader, name, uploadURL, token string, progress ProgressFunc) error {
	// Create a new multipart form body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Create a new form field for the file
	fileField, err := writer.CreateFormFile("file", name)
	if err != nil {
		return err
	}

	// Copy the file data to the form field
	_, err = io.Copy(fileField, r)
	if err != nil {
		return err
	}

	// Close the multipart form
	err = writer.Close()
	if err != nil {
		return err
	}

	totalSize := body.Len()
	dongSize := int64(0)
	pr := &ProgressReader{body, func(r int64) {
		if r > 0 {
			dongSize += r
			if progress != nil {
				progress(dongSize, int64(totalSize))
			}
		}
	}}

	// Create a new HTTP request with the form data
	request, err := http.NewRequest("POST", uploadURL, pr)
	if err != nil {
		return fmt.Errorf("new request error %s", err.Error())
	}

	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("Authorization", "Bearer "+token)
	request = request.WithContext(ctx)

	// Create an HTTP client and send the request
	client := http.DefaultClient
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("do error %s", err.Error())
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("http StatusCode %d", response.StatusCode)
	}

	b, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	type Result struct {
		Code int    `json:"code"`
		Err  int    `json:"err"`
		Msg  string `json:"msg"`
	}

	var ret Result
	if err := json.Unmarshal(b, &ret); err != nil {
		return err
	}

	if ret.Code != 0 {
		return fmt.Errorf(ret.Msg)
	}
	return nil
}

func getFileType(filePath string) (string, error) {
	fileType := FileTypeFile
	if fileInfo, err := os.Stat(filePath); err != nil {
		return "", err
	} else if fileInfo.IsDir() {
		fileType = FileTypeFolder
	}

	return string(fileType), nil
}

func getFastNode(candidates []*client.CandidateIPInfo) []*client.CandidateIPInfo {
	if len(candidates) == 0 {
		return make([]*client.CandidateIPInfo, 0)
	}

	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}
	lock := &sync.Mutex{}
	fastCandidates := make([]*client.CandidateIPInfo, 0)

	acquireFastNode := func(ctx context.Context, wg *sync.WaitGroup, candidate *client.CandidateIPInfo) error {
		defer wg.Done()

		request, err := http.NewRequest("GET", candidate.ExternalURL, nil)
		if err != nil {
			return err
		}
		request = request.WithContext(ctx)

		// Create an HTTP client and send the request
		client := http.DefaultClient
		_, err = client.Do(request)
		if err != nil {
			return fmt.Errorf("do error %s", err.Error())
		}
		cancel()

		lock.Lock()
		fastCandidates = append(fastCandidates, candidate)
		lock.Unlock()
		return nil
	}

	for _, candidate := range candidates {
		wg.Add(1)

		go acquireFastNode(ctx, wg, candidate)

	}
	wg.Wait()

	return fastCandidates
}
