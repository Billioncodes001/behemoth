package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/behemoth/db"
	actool "github.com/Autumn-27/norma/tool"
)

// save_artifact / list_artifacts: the loot vault tools. Agents call
// save_artifact for every database dump, config file, screenshot or loot blob
// they produce so it lands in <dataDir>/artifacts, is attributed to the right
// company/asset, and shows up on the Assets page "Files" tab.

// artifactTools returns the artifact agent tools.
func (s *Server) artifactTools() []actool.CoreTool {
	return []actool.CoreTool{s.toolSaveArtifact(), s.toolListArtifacts()}
}

// toolSaveArtifact exposes save_artifact.
func (s *Server) toolSaveArtifact() actool.CoreTool {
	return wrTool("save_artifact",
		"Save a file/artifact into the per-company loot vault (Assets page → Files): inline text content (content), an existing local file (path), or a downloaded URL (url). Every artifact is hashed, stored under <dataDir>/artifacts, and linked to its company (auto-resolved from source_url when company_id is omitted), the asset the URL belongs to, and the task. Use it for every database dump, config backup, screenshot, wordlist result or evidence file an agent produces.",
		objSchema(map[string]any{
			"name":        strParam("Display name (defaults to the filename)"),
			"content":     strParam("Inline text content to store (e.g. a database dump, JSON, notes)"),
			"path":        strParam("Path of an existing local file to store (absolute, or relative to the task working directory)"),
			"url":         strParam("URL to download and store (e.g. a discovered backup archive or the page the artifact came from)"),
			"filename":    strParam("Stored filename (defaults to the base name of path/url)"),
			"kind":        map[string]any{"type": "string", "enum": db.ArtifactKinds, "description": "Artifact kind (auto-detected from mime/filename when omitted)"},
			"mime":        strParam("MIME type (auto-detected when omitted)"),
			"source_url":  strParam("URL the artifact was scanned/fetched from — used to auto-link the company + asset"),
			"source_tool": strParam("Tool or technique that produced it, e.g. sqlmap, secretsdump, browser_inspect"),
			"description": strParam("Free-form description shown in the Files tab"),
			"company_id":  map[string]any{"type": "integer", "description": "Owning company id (auto-resolved from source_url / linked asset when omitted)"},
			"asset_id":    map[string]any{"type": "integer", "description": "Related asset id (auto-resolved from source_url when omitted)"},
			"task_id":     map[string]any{"type": "integer", "description": "Related task id (defaults to the current task when running inside one)"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Name        string `json:"name"`
				Content     string `json:"content"`
				Path        string `json:"path"`
				URL         string `json:"url"`
				Filename    string `json:"filename"`
				Kind        string `json:"kind"`
				MIME        string `json:"mime"`
				SourceURL   string `json:"source_url"`
				SourceTool  string `json:"source_tool"`
				Description string `json:"description"`
				CompanyID   int64  `json:"company_id"`
				AssetID     int64  `json:"asset_id"`
				TaskID      int64  `json:"task_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input JSON: %v", err)), nil
			}
			if s.artifactStore() == nil {
				return actool.Errorf("artifact store is unavailable (no database)"), nil
			}

			var data []byte
			var fallbackName string
			switch {
			case strings.TrimSpace(a.Content) != "":
				data = []byte(a.Content)
				fallbackName = "artifact.txt"
				if len(data) > maxArtifactInlineBytes {
					return actool.Errorf(fmt.Sprintf("inline content exceeds %d bytes; write it to a file first and pass path", maxArtifactInlineBytes)), nil
				}
			case strings.TrimSpace(a.Path) != "":
				abs, err := s.resolveArtifactSourcePath(a.Path, a.TaskID)
				if err != nil {
					return jsonResult(map[string]any{"error": err.Error()})
				}
				info, statErr := os.Stat(abs)
				if statErr != nil {
					return jsonResult(map[string]any{"error": fmt.Sprintf("path not found: %s", abs)})
				}
				if info.IsDir() {
					return jsonResult(map[string]any{"error": "path is a directory; provide a file path"})
				}
				if info.Size() > maxArtifactBytes {
					return jsonResult(map[string]any{"error": fmt.Sprintf("file exceeds %d bytes", maxArtifactBytes)})
				}
				data, statErr = os.ReadFile(abs)
				if statErr != nil {
					return jsonResult(map[string]any{"error": statErr.Error()})
				}
				fallbackName = filepath.Base(abs)
			case strings.TrimSpace(a.URL) != "":
				fetched, err := s.downloadArtifactURL(ctx, a.URL)
				if err != nil {
					return jsonResult(map[string]any{"error": err.Error()})
				}
				data = fetched
				fallbackName = artifactURLBasename(a.URL)
			default:
				return actool.Errorf("one of content, path or url is required"), nil
			}

			var companyID, assetID *int64
			if a.CompanyID > 0 {
				v := a.CompanyID
				companyID = &v
			}
			if a.AssetID > 0 {
				v := a.AssetID
				assetID = &v
			}
			var taskPtr *int64
			if a.TaskID > 0 {
				v := a.TaskID
				taskPtr = &v
			}
			artifact, err := s.saveArtifact(artifactSaveInput{
				Name:        firstNonEmpty(a.Name, a.Filename, fallbackName),
				Filename:    firstNonEmpty(a.Filename, fallbackName),
				Kind:        a.Kind,
				MIME:        a.MIME,
				SourceURL:   firstNonEmpty(a.SourceURL, a.URL),
				SourceTool:  a.SourceTool,
				Description: a.Description,
				CompanyID:   companyID,
				TaskID:      taskPtr,
				AssetID:     assetID,
				Data:        data,
			})
			if err != nil {
				return jsonResult(map[string]any{"error": err.Error()})
			}
			return jsonResult(map[string]any{
				"saved":        true,
				"artifact":     artifact,
				"instructions": "The file now appears on Assets → Files, linked to its company/source. Reference it by id in findings.",
			})
		})
}

// resolveArtifactSourcePath maps a user-supplied path to an existing readable
// file, preferring the task working directory for relative paths.
func (s *Server) resolveArtifactSourcePath(raw string, taskID int64) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p), nil
	}
	candidates := []string{}
	if taskID > 0 {
		candidates = append(candidates, filepath.Join(s.dataDir, "tasks", fmt.Sprint(taskID), p))
	}
	candidates = append(candidates, filepath.Join(s.dataDir, p), filepath.Clean(p))
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c, nil
		}
	}
	// Default to the first candidate so the caller's error mentions the likely path.
	if taskID > 0 {
		return filepath.Join(s.dataDir, "tasks", fmt.Sprint(taskID), p), nil
	}
	return filepath.Join(s.dataDir, p), nil
}

// downloadArtifactURL fetches a URL (proxy env-aware) up to maxArtifactBytes.
func (s *Server) downloadArtifactURL(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxArtifactBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxArtifactBytes {
		return nil, fmt.Errorf("download exceeds %d bytes", maxArtifactBytes)
	}
	return data, nil
}

// artifactURLBasename derives a filename from a URL.
func artifactURLBasename(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "download.bin"
	}
	name := strings.TrimSuffix(filepath.Base(u.Path), "/")
	if name == "" || name == "." || name == "/" {
		name = u.Hostname()
	}
	if name == "" {
		name = "download.bin"
	}
	return name
}

// toolListArtifacts exposes list_artifacts (read side of the loot vault).
func (s *Server) toolListArtifacts() actool.CoreTool {
	return roTool("list_artifacts",
		"List files previously saved to the loot vault (Assets page → Files), filterable by company, task, kind (text/image/dump/archive/binary/other) or substring query. Use it to check whether a dump/config/screenshot was already collected before re-fetching it.",
		objSchema(map[string]any{
			"company_id": map[string]any{"type": "integer", "description": "Only artifacts belonging to this company"},
			"task_id":    map[string]any{"type": "integer", "description": "Only artifacts produced by this task"},
			"kind":       map[string]any{"type": "string", "enum": db.ArtifactKinds, "description": "Filter by kind"},
			"query":      strParam("Substring match on name/filename/source URL/description"),
			"limit":      map[string]any{"type": "integer", "description": "Page size (default 50, max 500)"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				CompanyID int64  `json:"company_id"`
				TaskID    int64  `json:"task_id"`
				Kind      string `json:"kind"`
				Query     string `json:"query"`
				Limit     int    `json:"limit"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input JSON: %v", err)), nil
			}
			as := s.artifactStore()
			if as == nil {
				return actool.Errorf("artifact store is unavailable (no database)"), nil
			}
			items, total, err := as.List(db.ArtifactFilter{
				CompanyID: a.CompanyID,
				TaskID:    a.TaskID,
				Kind:      a.Kind,
				Query:     a.Query,
				Limit:     a.Limit,
			})
			if err != nil {
				return jsonResult(map[string]any{"error": err.Error()})
			}
			return jsonResult(map[string]any{"artifacts": items, "total": total})
		})
}
