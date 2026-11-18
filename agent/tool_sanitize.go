package agent

import (
	"context"
	"encoding/json"
	"iter"
	"regexp"
	"strings"

	"github.com/Autumn-27/norma/llm"
)

var (
	reLeadingParamTag  = regexp.MustCompile(`(?is)^\s*(?:<parameter=[^>]+>\s*)+`)
	reTrailingParamTag = regexp.MustCompile(`(?is)(?:\s*</parameter>\s*|\s*</function>\s*|\s*</tool_call>\s*)+$`)
	reXMLParamBlock    = regexp.MustCompile(`(?is)<parameter=([a-zA-Z0-9_.-]+)>\s*(.*?)\s*(?:</parameter>|$)`)
	reXMLFuncCall      = regexp.MustCompile(`(?is)<function=([a-zA-Z0-9_.-]+)>(.*?)</function>`)
	reXMLToolCall      = regexp.MustCompile(`(?is)<tool_call>\s*(.*?)\s*</tool_call>`)
)

var knownToolParamAliases = map[string]map[string][]string{
	"skill": {
		"name": {"skill", "skill_name", "skillName", "tool", "tool_name"},
		"args": {"arguments", "context", "input", "params"},
	},
	"bash": {
		"command": {"cmd", "script", "bash", "shell", "code"},
	},
	"read": {
		"file_path": {"path", "file", "filepath", "filename"},
	},
	"write": {
		"file_path": {"path", "file", "filepath", "filename"},
		"content":   {"text", "body", "data", "code"},
	},
	"edit": {
		"file_path":  {"path", "file", "filepath", "filename"},
		"old_string": {"old_text", "old", "search", "find"},
		"new_string": {"new_text", "new", "replace", "replacement"},
	},
	"multiedit": {
		"file_path": {"path", "file", "filepath", "filename"},
	},
	"ls": {
		"path": {"file_path", "dir", "directory", "folder", "target"},
	},
	"glob": {
		"pattern": {"glob", "query", "file_pattern"},
		"path":    {"file_path", "dir", "directory", "folder"},
	},
	"grep": {
		"pattern": {"query", "regex", "search", "term"},
		"path":    {"file_path", "dir", "directory", "folder"},
	},
	"webfetch": {
		"url": {"uri", "link", "target", "endpoint"},
	},
	"web_search": {
		"query": {"q", "search", "keyword", "keywords", "term"},
	},
}

func cleanParamString(s string) string {
	cleaned := reLeadingParamTag.ReplaceAllString(s, "")
	cleaned = reTrailingParamTag.ReplaceAllString(cleaned, "")
	if cleaned != s {
		return strings.TrimSpace(cleaned)
	}
	return s
}

func cleanJSONValue(v any) any {
	switch val := v.(type) {
	case string:
		return cleanParamString(val)
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, elem := range val {
			cleanKey := strings.TrimSpace(cleanParamString(k))
			out[cleanKey] = cleanJSONValue(elem)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, elem := range val {
			out[i] = cleanJSONValue(elem)
		}
		return out
	default:
		return v
	}
}

// SanitizeToolInput repairs malformed JSON / XML parameter tags and maps common
// parameter aliases (such as {"skill": "web-vuln-exploitation"} -> {"name": "web-vuln-exploitation"})
// against the tool's JSON schema.
func SanitizeToolInput(toolName string, raw json.RawMessage, schema map[string]any) json.RawMessage {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return json.RawMessage("{}")
	}
	if strings.HasPrefix(s, "```") {
		if nl := strings.IndexByte(s, '\n'); nl >= 0 {
			s = strings.TrimSpace(s[nl+1:])
		}
		s = strings.TrimSpace(strings.TrimSuffix(s, "```"))
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil || m == nil {
		matches := reXMLParamBlock.FindAllStringSubmatch(s, -1)
		if len(matches) > 0 {
			m = make(map[string]any, len(matches))
			for _, sub := range matches {
				m[strings.TrimSpace(sub[1])] = strings.TrimSpace(cleanParamString(sub[2]))
			}
		} else {
			var strVal string
			if err := json.Unmarshal([]byte(s), &strVal); err == nil && strings.TrimSpace(strVal) != "" {
				m = map[string]any{"_bare": cleanParamString(strVal)}
			} else {
				return raw
			}
		}
	}

	if cleaned, ok := cleanJSONValue(m).(map[string]any); ok {
		m = cleaned
	}

	lowerTool := strings.ToLower(strings.TrimSpace(toolName))
	if aliasesByCanonical, ok := knownToolParamAliases[lowerTool]; ok {
		for canonical, aliases := range aliasesByCanonical {
			if hasNonEmptyValue(m, canonical) {
				continue
			}
			for _, alias := range aliases {
				if val, exists := m[alias]; exists && isNonEmptyVal(val) {
					m[canonical] = val
					delete(m, alias)
					break
				}
			}
		}
	}

	if lowerTool == "skill" {
		if nameVal, ok := m["name"].(string); ok {
			lines := strings.Split(strings.TrimSpace(nameVal), "\n")
			last := strings.TrimSpace(lines[len(lines)-1])
			m["name"] = strings.Trim(last, `"'`+"`")
		}
	}

	applySchemaAliasFallback(m, schema)
	delete(m, "_bare")
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

func applySchemaAliasFallback(m map[string]any, schema map[string]any) {
	if schema == nil {
		return
	}
	reqKeys := schemaRequiredStrings(schema["required"])
	props, _ := schema["properties"].(map[string]any)
	var missingReq []string
	for _, rk := range reqKeys {
		if !hasNonEmptyValue(m, rk) {
			missingReq = append(missingReq, rk)
		}
	}
	if len(missingReq) == 0 {
		return
	}
	globalAliases := map[string][]string{
		"name":      {"skill", "skill_name", "tool", "tool_name", "id", "key", "title", "_bare"},
		"command":   {"cmd", "script", "bash", "shell", "_bare"},
		"file_path": {"path", "file", "filepath", "filename", "_bare"},
		"path":      {"file_path", "file", "filepath", "dir", "directory", "_bare"},
		"query":     {"q", "search", "pattern", "keyword", "_bare"},
		"url":       {"uri", "link", "target", "endpoint", "_bare"},
		"task_id":   {"id", "task", "taskId", "_bare"},
	}
	var stillMissing []string
	for _, rk := range missingReq {
		mapped := false
		for _, alias := range globalAliases[rk] {
			if val, exists := m[alias]; exists && isNonEmptyVal(val) {
				if props == nil || props[alias] == nil {
					m[rk] = val
					delete(m, alias)
					mapped = true
					break
				}
			}
		}
		if !mapped {
			stillMissing = append(stillMissing, rk)
		}
	}
	if len(stillMissing) == 1 && len(props) > 0 {
		var unknownKeys []string
		for k := range m {
			if _, defined := props[k]; !defined {
				unknownKeys = append(unknownKeys, k)
			}
		}
		if len(unknownKeys) == 1 {
			uk := unknownKeys[0]
			m[stillMissing[0]] = m[uk]
			delete(m, uk)
		}
	}
}

func hasNonEmptyValue(m map[string]any, key string) bool {
	v, ok := m[key]
	return ok && isNonEmptyVal(v)
}

func isNonEmptyVal(v any) bool {
	if v == nil {
		return false
	}
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s) != ""
	}
	return true
}

func schemaRequiredStrings(v any) []string {
	switch arr := v.(type) {
	case []string:
		return arr
	case []any:
		out := make([]string, 0, len(arr))
		for _, e := range arr {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func findToolSchema(name string, tools []llm.ToolSchema) map[string]any {
	for _, t := range tools {
		if t.Name == name || strings.EqualFold(t.Name, name) {
			return t.InputSchema
		}
	}
	return nil
}

func extractEmbeddedToolCalls(text string, tools []llm.ToolSchema) (cleanText string, calls []llm.ContentBlock) {
	if !strings.Contains(text, "<function=") && !strings.Contains(text, "<tool_call>") {
		return text, nil
	}
	cleanText = text

	funcMatches := reXMLFuncCall.FindAllStringSubmatch(cleanText, -1)
	for i, fm := range funcMatches {
		tName := strings.TrimSpace(fm[1])
		rawIn := SanitizeToolInput(tName, json.RawMessage(fm[2]), findToolSchema(tName, tools))
		calls = append(calls, llm.ContentBlock{
			Type:  llm.BlockToolUse,
			ID:    "xmlcall_" + strings.ToLower(tName) + "_" + string(rune('a'+i)),
			Name:  tName,
			Input: rawIn,
		})
	}
	if len(funcMatches) > 0 {
		cleanText = reXMLFuncCall.ReplaceAllString(cleanText, "")
		cleanText = reXMLToolCall.ReplaceAllString(cleanText, "")
		return strings.TrimSpace(cleanText), calls
	}

	tcMatches := reXMLToolCall.FindAllStringSubmatch(cleanText, -1)
	for i, tm := range tcMatches {
		inner := strings.TrimSpace(tm[1])
		var parsed struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
			Input     json.RawMessage `json:"input"`
		}
		if json.Unmarshal([]byte(inner), &parsed) == nil && parsed.Name != "" {
			argBytes := parsed.Arguments
			if len(argBytes) == 0 {
				argBytes = parsed.Input
			}
			var argStr string
			if json.Unmarshal(argBytes, &argStr) == nil {
				argBytes = json.RawMessage(argStr)
			}
			rawIn := SanitizeToolInput(parsed.Name, argBytes, findToolSchema(parsed.Name, tools))
			calls = append(calls, llm.ContentBlock{
				Type:  llm.BlockToolUse,
				ID:    "xmltc_" + strings.ToLower(parsed.Name) + "_" + string(rune('a'+i)),
				Name:  parsed.Name,
				Input: rawIn,
			})
		}
	}
	if len(calls) > 0 {
		cleanText = reXMLToolCall.ReplaceAllString(cleanText, "")
	}
	return strings.TrimSpace(cleanText), calls
}

type toolSanitizingProvider struct {
	inner llm.Provider
}

func wrapToolSanitizingProvider(p llm.Provider) llm.Provider {
	if p == nil {
		return nil
	}
	return &toolSanitizingProvider{inner: p}
}

func (p *toolSanitizingProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		var (
			buildingTool  bool
			curToolName   string
			curToolBuf    strings.Builder
			sawNativeTool bool
			textBuf       strings.Builder
		)
		flushTool := func() bool {
			if !buildingTool {
				return true
			}
			buildingTool = false
			raw := curToolBuf.String()
			curToolBuf.Reset()
			schema := findToolSchema(curToolName, req.Tools)
			sanitized := SanitizeToolInput(curToolName, json.RawMessage(raw), schema)
			return yield(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: string(sanitized)}, nil)
		}

		for ev, err := range p.inner.Stream(ctx, req) {
			if err != nil {
				_ = flushTool()
				yield(llm.StreamEvent{}, err)
				return
			}
			if ev.Type == llm.SEToolInputJSON && buildingTool {
				curToolBuf.WriteString(ev.Text)
				continue
			}
			if !flushTool() {
				return
			}
			switch ev.Type {
			case llm.SEToolUseStart:
				sawNativeTool = true
				buildingTool = true
				curToolName = ev.ToolName
				curToolBuf.Reset()
			case llm.SETextDelta:
				textBuf.WriteString(ev.Text)
			case llm.SEMessageDelta:
				if !sawNativeTool && textBuf.Len() > 0 {
					_, embedded := extractEmbeddedToolCalls(textBuf.String(), req.Tools)
					if len(embedded) > 0 {
						sawNativeTool = true
						for _, tc := range embedded {
							if !yield(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: tc.ID, ToolName: tc.Name}, nil) {
								return
							}
							if !yield(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: string(tc.Input)}, nil) {
								return
							}
						}
						ev.StopReason = "tool_use"
					}
				}
			}
			if !yield(ev, nil) {
				return
			}
		}
		_ = flushTool()
	}
}

func (p *toolSanitizingProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	msg, stop, usage, err := p.inner.Complete(ctx, req)
	if err != nil {
		return msg, stop, usage, err
	}
	sawTool := false
	for i, b := range msg.Content {
		if b.Type == llm.BlockToolUse {
			sawTool = true
			schema := findToolSchema(b.Name, req.Tools)
			msg.Content[i].Input = SanitizeToolInput(b.Name, b.Input, schema)
		}
	}
	if !sawTool {
		var newBlocks, extracted []llm.ContentBlock
		for _, b := range msg.Content {
			if b.Type == llm.BlockText {
				cleaned, calls := extractEmbeddedToolCalls(b.Text, req.Tools)
				if len(calls) > 0 {
					if cleaned != "" {
						newBlocks = append(newBlocks, llm.TextBlock(cleaned))
					}
					extracted = append(extracted, calls...)
					continue
				}
			}
			newBlocks = append(newBlocks, b)
		}
		if len(extracted) > 0 {
			msg.Content = append(newBlocks, extracted...)
			stop = "tool_use"
		}
	}
	return msg, stop, usage, nil
}
