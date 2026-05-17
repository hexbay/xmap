package input

import (
	"bufio"
	"bytes"
	"github.com/hexbay/xmap/pkg/types"
	"io"
	"os"
	"strings"
)

// lineCount 计算文件的行数
func lineCount(r io.Reader) (int, error) {
	buf := make([]byte, 32*1024)
	count := 0
	lineSep := []byte{'\n'}

	for {
		c, err := r.Read(buf)
		count += bytes.Count(buf[:c], lineSep)
		switch {
		case err == io.EOF:
			return count, nil
		case err != nil:
			return count, err
		}
	}
}

// FileInputProvider 是一个文件输入提供者实现
type FileInputProvider struct {
	file     *os.File
	filename string
	count    int
}

// NewFileInputProvider 创建一个新的文件输入提供者
func NewFileInputProvider(filename string) (*FileInputProvider, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	// 计算行数
	count, err := lineCount(file)
	if err != nil {
		func() {
			_ = file.Close()
		}()
		return nil, err
	}

	// 重置文件指针
	_, err = file.Seek(0, 0)
	if err != nil {
		func() {
			_ = file.Close()
		}()
		return nil, err
	}

	return &FileInputProvider{
		file:     file,
		filename: filename,
		count:    count,
	}, nil
}

// Count 返回输入项的总数
func (f *FileInputProvider) Count() int {
	return f.count
}

// Scan 扫描所有输入项
func (f *FileInputProvider) Scan(callback func(value *types.ScanTarget) bool) {
	defer f.file.Seek(0, 0)

	scanner := bufio.NewScanner(f.file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // 跳过空行和注释行
		}

		target := &types.ScanTarget{
			Raw: line,
		}

		if !callback(target) {
			break
		}
	}
}

// Close 关闭输入提供者
func (f *FileInputProvider) Close() {
	if f.file != nil {
		func() {
			_ = f.file.Close()
		}()

	}
}
