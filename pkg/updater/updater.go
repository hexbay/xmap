package updater

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const githubLatestReleaseURL = "https://api.github.com/repos/tongchengbin/xmap/releases/latest"

type releaseInfo struct {
	TagName string         `json:"tag_name"`
	Assets  []releaseAsset `json:"assets"`
}

type releaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// UpdateToLatest downloads and installs the latest xmap release for this platform.
func UpdateToLatest(ctx context.Context, currentVersion string) error {
	release, err := fetchLatestRelease(ctx)
	if err != nil {
		return err
	}
	if sameVersion(currentVersion, release.TagName) {
		fmt.Printf("xmap 已是最新版本: %s\n", release.TagName)
		return nil
	}
	asset, err := selectAsset(release.Assets)
	if err != nil {
		return err
	}
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取当前程序路径失败: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("解析当前程序路径失败: %w", err)
	}
	tmpDir, err := os.MkdirTemp("", "xmap-update-*")
	if err != nil {
		return fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, asset.Name)
	if err := downloadFile(ctx, asset.BrowserDownloadURL, archivePath); err != nil {
		return err
	}
	newBinary, err := extractBinary(archivePath, tmpDir)
	if err != nil {
		return err
	}
	if err := installBinary(newBinary, exePath); err != nil {
		return err
	}
	fmt.Printf("xmap 已更新到 %s\n", release.TagName)
	return nil
}

func fetchLatestRelease(ctx context.Context) (*releaseInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubLatestReleaseURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "xmap-updater")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("查询最新版本失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("查询最新版本失败: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var release releaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("解析最新版本信息失败: %w", err)
	}
	if release.TagName == "" {
		return nil, fmt.Errorf("最新版本信息缺少 tag")
	}
	return &release, nil
}

func sameVersion(current, latest string) bool {
	return strings.TrimPrefix(current, "v") == strings.TrimPrefix(latest, "v")
}

func selectAsset(assets []releaseAsset) (*releaseAsset, error) {
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	for _, asset := range assets {
		name := strings.ToLower(asset.Name)
		if strings.Contains(name, goos) && strings.Contains(name, goarch) &&
			(strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".zip")) {
			return &asset, nil
		}
	}
	return nil, fmt.Errorf("未找到适用于 %s/%s 的发布包", goos, goarch)
}

func downloadFile(ctx context.Context, url, dst string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("下载更新包失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载更新包失败: HTTP %d", resp.StatusCode)
	}
	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("创建更新包失败: %w", err)
	}
	defer out.Close()
	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("保存更新包失败: %w", err)
	}
	return nil
}

func extractBinary(archivePath, dstDir string) (string, error) {
	lower := strings.ToLower(archivePath)
	switch {
	case strings.HasSuffix(lower, ".tar.gz"):
		return extractTarGzBinary(archivePath, dstDir)
	case strings.HasSuffix(lower, ".zip"):
		return extractZipBinary(archivePath, dstDir)
	default:
		return "", fmt.Errorf("不支持的更新包格式: %s", archivePath)
	}
}

func extractTarGzBinary(archivePath, dstDir string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if header.FileInfo().IsDir() || !looksLikeXmapBinary(header.Name) {
			continue
		}
		return writeExtractedBinary(tr, dstDir, filepath.Base(header.Name), header.FileInfo().Mode())
	}
	return "", fmt.Errorf("更新包中未找到 xmap 可执行文件")
}

func extractZipBinary(archivePath, dstDir string) (string, error) {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", err
	}
	defer r.Close()
	for _, file := range r.File {
		if file.FileInfo().IsDir() || !looksLikeXmapBinary(file.Name) {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return "", err
		}
		defer rc.Close()
		return writeExtractedBinary(rc, dstDir, filepath.Base(file.Name), file.FileInfo().Mode())
	}
	return "", fmt.Errorf("更新包中未找到 xmap 可执行文件")
}

func looksLikeXmapBinary(name string) bool {
	base := strings.ToLower(filepath.Base(name))
	if runtime.GOOS == "windows" {
		return strings.HasPrefix(base, "xmap") && strings.HasSuffix(base, ".exe")
	}
	return strings.HasPrefix(base, "xmap")
}

func writeExtractedBinary(src io.Reader, dstDir, name string, mode os.FileMode) (string, error) {
	dst := filepath.Join(dstDir, name)
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode|0755)
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err := io.Copy(out, src); err != nil {
		return "", err
	}
	return dst, nil
}

func installBinary(newBinary, currentBinary string) error {
	if runtime.GOOS == "windows" {
		return installBinaryWindows(newBinary, currentBinary)
	}
	info, err := os.Stat(currentBinary)
	if err != nil {
		return err
	}
	if err := os.Chmod(newBinary, info.Mode()|0755); err != nil {
		return err
	}
	return os.Rename(newBinary, currentBinary)
}

func installBinaryWindows(newBinary, currentBinary string) error {
	updatePath := currentBinary + ".new"
	if err := copyFile(newBinary, updatePath); err != nil {
		return err
	}
	scriptPath := filepath.Join(os.TempDir(), "xmap-update.bat")
	script := fmt.Sprintf(`@echo off
ping 127.0.0.1 -n 2 > nul
move /Y "%s" "%s" > nul
del "%%~f0"
`, updatePath, currentBinary)
	if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
		return fmt.Errorf("创建Windows更新脚本失败: %w", err)
	}
	cmd := exec.Command("cmd", "/C", "start", "", "/MIN", scriptPath)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动Windows更新脚本失败: %w", err)
	}
	fmt.Println("Windows将在当前进程退出后完成替换。")
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
