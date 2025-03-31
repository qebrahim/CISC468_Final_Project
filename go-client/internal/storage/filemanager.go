package storage

import (
	"io/ioutil"
	"os"
	"path/filepath"
)

type FileManager struct {
	baseDir string
}

func NewFileManager(baseDir string) *FileManager {
	return &FileManager{baseDir: baseDir}
}

func (fm *FileManager) SaveFile(filename string, data []byte) error {
	filePath := filepath.Join(fm.baseDir, filename)
	return ioutil.WriteFile(filePath, data, 0644)
}

func (fm *FileManager) LoadFile(filename string) ([]byte, error) {
	filePath := filepath.Join(fm.baseDir, filename)
	return ioutil.ReadFile(filePath)
}

func (fm *FileManager) ListFiles() ([]string, error) {
	files, err := ioutil.ReadDir(fm.baseDir)
	if err != nil {
		return nil, err
	}

	var fileList []string
	for _, file := range files {
		if !file.IsDir() {
			fileList = append(fileList, file.Name())
		}
	}
	return fileList, nil
}

func (fm *FileManager) DeleteFile(filename string) error {
	filePath := filepath.Join(fm.baseDir, filename)
	return os.Remove(filePath)
}
