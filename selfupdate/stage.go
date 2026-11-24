package selfupdate

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/Autumn-27/behemoth/internal/httpidentity"
)

// sumsAsset 是 release.yml 生成的校验和清单，覆盖 Release 里全部 zip。
const sumsAsset = "SHA256SUMS"

// maxBinarySize 限制解压出来的二进制体积，防止畸形 zip 把磁盘写满。
const maxBinarySize = 512 << 20 // 512 MiB

// Phase 是升级过程中的阶段，直接用作 SSE 事件里的 phase 字段。
type Phase string

const (
	PhaseIdle     Phase = "idle"
	PhaseDownload Phase = "downloading"
	PhaseVerify   Phase = "verifying"
	PhaseExtract  Phase = "extracting"
	PhaseStaged   Phase = "staged"
	PhaseFailed   Phase = "failed"
)

// Progress 由调用方提供，用来把进度推给前端。pct 仅在下载阶段有意义（0-100），
// 其余阶段传 -1。
type Progress func(ph Phase, pct int, msg string)

// Stage 下载指定 Release 的当前平台发布包，校验后把新二进制暂存为 behemoth.new。
//
// 走的是完整 zip 而不是裸二进制，理由有两个：现有 Release 的 SHA256SUMS 本来就
// 只覆盖 zip，走 zip 不需要改 CI，也能兼容已经发布出去的历史版本；zip 里还带着
// skills/，为将来同步内置 skill 留了口子。代价只是多下载 skills 那几百 KB。
//
// 函数返回即代表暂存完成，调用方随后优雅关闭并以 ExitRestart 退出。
func Stage(ctx context.Context, c *http.Client, rel *Release, currentVersion string, prog Progress) error {
	if prog == nil {
		prog = func(Phase, int, string) {}
	}
	p, err := ResolvePaths()
	if err != nil {
		return err
	}
	return stageAt(ctx, c, rel, currentVersion, prog, p)
}

// stageAt keeps downloads and executable replacement testable in an isolated directory.
func stageAt(ctx context.Context, c *http.Client, rel *Release, currentVersion string, prog Progress, p Paths) error {
	if err := checkWritable(p.Dir); err != nil {
		return err
	}

	name := AssetName(rel.TagName, runtime.GOOS, runtime.GOARCH)
	asset, ok := rel.FindAsset(name)
	if !ok {
		return fmt.Errorf("This release does not provide a package for %s/%s (missing %s)", runtime.GOOS, runtime.GOARCH, name)
	}

	prog(PhaseDownload, 0, "Fetching checksum manifest…")
	sums, err := fetchSums(ctx, c, rel)
	if err != nil {
		return err
	}
	want, ok := sums[name]
	if !ok {
		return fmt.Errorf("%s does not list %s; refusing to install unverified binary", sumsAsset, name)
	}

	zipPath := p.New + ".zip.part"
	binPath := p.New + ".part"
	defer func() {
		_ = os.Remove(zipPath)
		_ = os.Remove(binPath)
	}()

	prog(PhaseDownload, 0, fmt.Sprintf("Downloading %s (%s)…", name, humanSize(asset.Size)))
	got, err := download(ctx, c, asset, zipPath, prog)
	if err != nil {
		return err
	}

	prog(PhaseVerify, -1, "Verifying SHA256…")
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("SHA256 mismatch: expected %s, got %s (download corrupted or tampered)", short(want), short(got))
	}

	prog(PhaseExtract, -1, "Extracting and running smoke test…")
	if err := extractBinary(zipPath, binPath); err != nil {
		return err
	}
	if err := smokeTest(binPath); err != nil {
		return fmt.Errorf("New version cannot run on this system: %w", err)
	}

	binSum, err := fileSHA256(binPath)
	if err != nil {
		return fmt.Errorf("compute new binary checksum: %w", err)
	}
	if err := os.WriteFile(p.Sum, []byte(binSum), 0o644); err != nil {
		return fmt.Errorf("write checksum: %w", err)
	}
	if err := os.Rename(binPath, p.New); err != nil {
		_ = os.Remove(p.Sum)
		return fmt.Errorf("stage new version: %w", err)
	}

	if err := writeMarker(p.Marker, marker{
		From:     currentVersion,
		To:       strings.TrimPrefix(rel.TagName, "v"),
		StagedAt: time.Now().Unix(),
	}); err != nil {
		prog(PhaseStaged, -1, "Warning: The update marker could not be written. This update will not have automatic rollback protection.")
	}

	prog(PhaseStaged, 100, "New version staged; restarting…")
	return nil
}

func fetchSums(ctx context.Context, c *http.Client, rel *Release) (map[string]string, error) {
	asset, ok := rel.FindAsset(sumsAsset)
	if !ok {
		return nil, fmt.Errorf("Release is missing %s; cannot verify integrity, refusing update", sumsAsset)
	}
	body, err := get(ctx, c, asset.URL)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", sumsAsset, err)
	}
	defer body.Close()

	raw, err := io.ReadAll(io.LimitReader(body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", sumsAsset, err)
	}
	out := parseSums(string(raw))
	if len(out) == 0 {
		return nil, fmt.Errorf("%s is empty or has an unrecognized format", sumsAsset)
	}
	return out, nil
}

// parseSums 解析 sha256sum 风格的清单，返回 文件名 → 十六进制摘要。
//
// 第一个字段必须是 64 位十六进制才收录。只按"恰好两个字段"判断是不够的——
// 任意一行两个单词的说明文字都会被当成合法条目，把垃圾值塞进摘要表，
// 真正的资产反而可能匹配到错误的摘要。
func parseSums(raw string) map[string]string {
	out := map[string]string{}
	for line := range strings.Lines(raw) {
		// 格式为 "<sha256>  <filename>"（sha256sum 用双空格；shasum 的二进制
		// 模式会给文件名加 * 前缀）。
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 || !isHexSHA256(fields[0]) {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name == "" {
			continue
		}
		out[name] = strings.ToLower(fields[0])
	}
	return out
}

func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// download 把资产写入 dst，同时计算 SHA256 并按 Content-Length 汇报进度。
func download(ctx context.Context, c *http.Client, a Asset, dst string, prog Progress) (string, error) {
	body, err := get(ctx, c, a.URL)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", a.Name, err)
	}
	defer body.Close()

	f, err := os.Create(dst)
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	pw := &progressWriter{total: a.Size, prog: prog, name: a.Name, last: time.Now()}
	if _, err := io.Copy(io.MultiWriter(f, h, pw), body); err != nil {
		return "", fmt.Errorf("download interrupted: %w", err)
	}
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("sync file to disk: %w", err)
	}
	if a.Size > 0 && pw.written != a.Size {
		return "", fmt.Errorf("incomplete download: expected %d bytes, got %d bytes", a.Size, pw.written)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// get 发起一个受白名单约束的 GET，返回响应体。
func get(ctx context.Context, c *http.Client, rawURL string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if err := checkURL(req.URL); err != nil {
		return nil, err
	}
	httpidentity.Apply(req)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp.Body, nil
}

// extractBinary 从发布包里取出 behemoth 可执行文件。
//
// 包内结构是 behemoth-<版本>-<os>-<arch>/behemoth，但这里按**基名**匹配而不是拼完整
// 路径：版本号在包名里出现过一次，拼错一个字符就整个升级失败，按基名找更耐改。
func extractBinary(zipPath, dst string) error {
	want := "behemoth"
	if runtime.GOOS == "windows" {
		want = "behemoth.exe"
	}
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open release archive: %w", err)
	}
	defer zr.Close()

	for _, entry := range zr.File {
		if entry.FileInfo().IsDir() || !strings.EqualFold(path.Base(entry.Name), want) {
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			return fmt.Errorf("read %s: %w", entry.Name, err)
		}
		defer rc.Close()

		f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return fmt.Errorf("write new binary: %w", err)
		}
		defer f.Close()

		n, err := io.Copy(f, io.LimitReader(rc, maxBinarySize+1))
		if err != nil {
			return fmt.Errorf("extract %s: %w", entry.Name, err)
		}
		if n > maxBinarySize {
			return fmt.Errorf("executable inside release archive exceeds %s; refusing extraction", humanSize(maxBinarySize))
		}
		if n == 0 {
			return fmt.Errorf("%s inside release archive is empty", want)
		}
		return f.Sync()
	}
	return fmt.Errorf("%s not found in release archive", want)
}

func checkWritable(dir string) error {
	probe, err := os.CreateTemp(dir, ".behemoth-update-probe-*")
	if err != nil {
		return fmt.Errorf("Application directory %s is not writable; automatic update unavailable (check permissions or update manually): %w", dir, err)
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	return nil
}

type progressWriter struct {
	total   int64
	written int64
	name    string
	prog    Progress
	last    time.Time
}

func (w *progressWriter) Write(b []byte) (int, error) {
	w.written += int64(len(b))
	if time.Since(w.last) < 300*time.Millisecond {
		return len(b), nil
	}
	w.last = time.Now()
	pct := -1
	if w.total > 0 {
		pct = int(w.written * 100 / w.total)
	}
	w.prog(PhaseDownload, pct, fmt.Sprintf("Downloading %s / %s", humanSize(w.written), humanSize(w.total)))
	return len(b), nil
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

func short(sum string) string {
	if len(sum) > 12 {
		return sum[:12] + "…"
	}
	return sum
}
