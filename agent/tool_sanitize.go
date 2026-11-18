package agent

import (
	"context"
	"encoding/json"
	"fmt"
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

func isContinuationUserMsg(m llm.Message) bool {
	if m.Role != llm.RoleUser {
		return false
	}
	t := strings.TrimSpace(m.Text())
	return strings.HasPrefix(t, "[System Continuation")
}

var primaryChatTools = map[string]bool{
	"Bash":                       true,
	"WebFetch":                   true,
	"web_search":                 true,
	"Skill":                      true,
	"Read":                       true,
	"ReadOutput":                 true,
	"Write":                      true,
	"Edit":                       true,
	"MultiEdit":                  true,
	"LS":                         true,
	"Glob":                       true,
	"Grep":                       true,
	"insert_assets":              true,
	"list_assets":                true,
	"add_company_scope":          true,
	"list_companies":             true,
	"report_finding":             true,
	"list_findings":              true,
	"spawn_task":                 true,
	"list_tasks":                 true,
	"pause_task":                 true,
	"get_task_graph":             true,
	"list_task_findings":         true,
	"add_task_hint":              true,
	"traffic_search":             true,
	"traffic_get":                true,
	"traffic_blob":               true,
	"create_skill":               true,
	"update_skill_file":          true,
	"generate_payload":           true,
	"check_patch_feeds":          true,
	"generate_vuln_exploit":      true,
	"search_ios_exploits":        true,
	"multi_engine_search":        true,
	"exploit_search":             true,
	"SearchExtraTools":           true,
	"ExecuteExtraTool":           true,
	"get_graph":                  true,
	"add_node":                   true,
	"add_edge":                   true,
	"update_node":                true,
	"block_intent":               true,
	"spawn_work":                 true,
	"wait_for_work":              true,
	"steer_work":                 true,
	"kill_work":                  true,
	"inspect_work":               true,
	"emit_intents":               true,
	"emit_task_title":            true,
	"mark_done":                  true,
	"check_coverage":             true,
	"shell_open":                 true,
	"shell_send":                 true,
	"shell_read":                 true,
	"shell_close":                true,
	"bind_finding_traffic":       true,
	"record_intelligence":        true,
	"get_finding_retest_context": true,
	"complete_finding_retest":    true,
}

// mirrorToolBlocksToText ensures that OpenAI-compatible gateways whose ChatML
// templates ignore assistant.tool_calls (when content is empty) or skip role:"tool"
// messages still see every tool invocation and tool result inside assistant/user
// text content, while preserving the native BlockToolUse and BlockToolResult blocks.
func mirrorToolBlocksToText(msgs []llm.Message) []llm.Message {
	out := make([]llm.Message, len(msgs))
	for i, m := range msgs {
		cp := llm.Message{
			Role:    m.Role,
			Content: make([]llm.ContentBlock, len(m.Content)),
		}
		copy(cp.Content, m.Content)

		switch cp.Role {
		case llm.RoleAssistant:
			var toolDescs []string
			hasText := false
			for _, b := range cp.Content {
				if b.Type == llm.BlockText && strings.TrimSpace(b.Text) != "" {
					hasText = true
				}
				if b.Type == llm.BlockToolUse {
					inStr := string(b.Input)
					if len(inStr) > 300 {
						inStr = inStr[:300] + "..."
					}
					toolDescs = append(toolDescs, fmt.Sprintf("[Called tool %s(%s)]", b.Name, inStr))
				}
			}
			if len(toolDescs) > 0 {
				summary := strings.Join(toolDescs, "\n")
				if !hasText {
					cp.Content = append([]llm.ContentBlock{llm.TextBlock(summary)}, cp.Content...)
				} else {
					for j := range cp.Content {
						if cp.Content[j].Type == llm.BlockText {
							cp.Content[j].Text = strings.TrimSpace(cp.Content[j].Text) + "\n" + summary
							break
						}
					}
				}
			}
		case llm.RoleUser:
			var resTexts []string
			for _, b := range cp.Content {
				if b.Type == llm.BlockToolResult {
					var sb strings.Builder
					for _, cb := range b.Content {
						if cb.Type == llm.BlockText && cb.Text != "" {
							sb.WriteString(cb.Text)
						}
					}
					r := strings.TrimSpace(sb.String())
					if len(r) > 2500 {
						r = r[:2500] + "\n...[truncated]..."
					}
					status := "OK"
					if b.IsError {
						status = "ERROR"
					}
					resTexts = append(resTexts, fmt.Sprintf("[Tool Result (%s, status=%s)]:\n%s", b.ToolUseID, status, r))
				}
			}
			if len(resTexts) > 0 {
				mirrorBlock := llm.TextBlock(strings.Join(resTexts, "\n\n") + "\n\nContinue the operation based on the tool results above: invoke the next required tool (e.g., Bash, insert_assets, report_finding), or if all probing and asset/finding registration are complete, write your comprehensive final Markdown security assessment report.")
				cp.Content = append(cp.Content, mirrorBlock)
			}
		}
		out[i] = cp
	}
	return out
}
func prepareRequest(req llm.CompletionRequest) llm.CompletionRequest {
	if req.MaxTokens > 4096 {
		req.MaxTokens = 4096
	}
	if len(req.Tools) > 28 {
		filtered := make([]llm.ToolSchema, 0, len(primaryChatTools))
		for _, t := range req.Tools {
			if primaryChatTools[t.Name] || strings.HasPrefix(t.Name, "mcp__") {
				filtered = append(filtered, t)
			}
		}
		if len(filtered) >= 10 {
			req.Tools = filtered
		}
	}
	if len(req.Messages) >= 2 {
		cleaned := make([]llm.Message, 0, len(req.Messages))
		for i := 0; i < len(req.Messages); i++ {
			if i+1 < len(req.Messages) &&
				req.Messages[i].Role == llm.RoleAssistant &&
				len(req.Messages[i].ToolUses()) == 0 &&
				isContinuationUserMsg(req.Messages[i+1]) {
				if i+1 < len(req.Messages)-1 {
					i++
				}
				continue
			}
			cleaned = append(cleaned, req.Messages[i])
		}
		req.Messages = cleaned
	}
	req.Messages = mirrorToolBlocksToText(req.Messages)
	return req
}

func isMaxTokensContextError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return (strings.Contains(msg, "context_length_exceeded") || strings.Contains(msg, "exceeds the model's context size") || strings.Contains(msg, "maximum context length")) &&
		(strings.Contains(msg, "max_tokens") || strings.Contains(msg, "completion"))
}

func hasDegenerateRepetition(s string) bool {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	var nonEmpty []string
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if len(t) >= 12 {
			nonEmpty = append(nonEmpty, t)
		}
	}
	n := len(nonEmpty)
	if n >= 3 && nonEmpty[n-1] == nonEmpty[n-2] && nonEmpty[n-2] == nonEmpty[n-3] {
		return true
	}
	return false
}

func dedupRepeatedLines(s string) string {
	lines := strings.Split(s, "\n")
	var out []string
	var lastNonEmpty string
	repeatCount := 0
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t != "" && t == lastNonEmpty {
			repeatCount++
			if repeatCount >= 1 {
				continue
			}
		} else if t != "" {
			lastNonEmpty = t
			repeatCount = 0
		}
		out = append(out, l)
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

func (p *toolSanitizingProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	req = prepareRequest(req)
	isContTurn := len(req.Messages) > 0 && isContinuationUserMsg(req.Messages[len(req.Messages)-1])
	return func(yield func(llm.StreamEvent, error) bool) {
		for attempt := 0; attempt < 3; attempt++ {
			var (
				buildingTool  bool
				curToolName   string
				curToolBuf    strings.Builder
				sawNativeTool bool
				textBuf       strings.Builder
				bufferedEvs   []llm.StreamEvent
				buffering     = isContTurn && attempt < 2
				emittedAny    bool
				retryAttempt  bool
			)
			flushBuffered := func() bool {
				if !buffering {
					return true
				}
				buffering = false
				for _, bev := range bufferedEvs {
					emittedAny = true
					if !yield(bev, nil) {
						return false
					}
				}
				bufferedEvs = nil
				return true
			}
			flushTool := func() bool {
				if !buildingTool {
					return true
				}
				buildingTool = false
				raw := curToolBuf.String()
				curToolBuf.Reset()
				schema := findToolSchema(curToolName, req.Tools)
				sanitized := SanitizeToolInput(curToolName, json.RawMessage(raw), schema)
				emittedAny = true
				return yield(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: string(sanitized)}, nil)
			}

			streamCtx, cancelStream := context.WithCancel(ctx)
			for ev, err := range p.inner.Stream(streamCtx, req) {
				if err != nil {
					cancelStream()
					_ = flushTool()
					if !emittedAny && attempt == 0 && isMaxTokensContextError(err) && req.MaxTokens > 1024 {
						req.MaxTokens = 1024
						retryAttempt = true
						break
					}
					if retryAttempt {
						break
					}
					yield(llm.StreamEvent{}, err)
					return
				}
				if ev.Type == llm.SEToolInputJSON && buildingTool {
					curToolBuf.WriteString(ev.Text)
					continue
				}
				if !flushTool() {
					cancelStream()
					return
				}
				switch ev.Type {
				case llm.SEToolUseStart:
					sawNativeTool = true
					if !flushBuffered() {
						cancelStream()
						return
					}
					buildingTool = true
					curToolName = ev.ToolName
					curToolBuf.Reset()
				case llm.SETextDelta:
					textBuf.WriteString(ev.Text)
					if !sawNativeTool && hasDegenerateRepetition(textBuf.String()) {
						cancelStream()
						if attempt < 2 && len(req.Messages) > 0 {
							lastIdx := len(req.Messages) - 1
							req.Messages[lastIdx] = llm.UserText(req.Messages[lastIdx].Text() + "\n\nCRITICAL: Do not repeat sentences—invoke a tool (such as Bash or insert_assets) immediately, or output your final structured markdown report.")
							retryAttempt = true
						}
						break
					}
					if buffering {
						bufferedEvs = append(bufferedEvs, ev)
						continue
					}
				case llm.SEThinkingDelta, llm.SEThinkingSignature, llm.SEMessageStart:
					if buffering {
						bufferedEvs = append(bufferedEvs, ev)
						continue
					}
				case llm.SEMessageDelta:
					if !sawNativeTool && textBuf.Len() > 0 {
						_, embedded := extractEmbeddedToolCalls(textBuf.String(), req.Tools)
						if len(embedded) > 0 {
							sawNativeTool = true
							if !flushBuffered() {
								cancelStream()
								return
							}
							for _, tc := range embedded {
								emittedAny = true
								if !yield(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: tc.ID, ToolName: tc.Name}, nil) {
									cancelStream()
									return
								}
								if !yield(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: string(tc.Input)}, nil) {
									cancelStream()
									return
								}
							}
							ev.StopReason = "tool_use"
						}
					}
					if buffering && !sawNativeTool && attempt < 2 {
						txt := strings.TrimSpace(textBuf.String())
						// On a continuation turn (where Hooks.Stop already demanded a tool call),
						// any response without a tool call that is not a comprehensive multi-section
						// final report (>= 500 chars with markdown headings) must be retried so
						// harness does not exit early while stopHookActive is true.
						isFullReport := len(txt) >= 500 && (strings.Contains(txt, "## ") || strings.Contains(txt, "### "))
						if !isFullReport {
							cancelStream()
							lastIdx := len(req.Messages) - 1
							req.Messages[lastIdx] = llm.UserText(req.Messages[lastIdx].Text() + "\n\nCRITICAL: Do not respond with a status sentence—you MUST emit a tool_calls function call (such as Bash, insert_assets, or report_finding) right now.")
							retryAttempt = true
							break
						}
					}
					if !flushBuffered() {
						cancelStream()
						return
					}
				}
				if retryAttempt {
					break
				}
				if ev.Type == llm.SETextDelta || ev.Type == llm.SEThinkingDelta || ev.Type == llm.SEToolUseStart {
					emittedAny = true
				}
				if !yield(ev, nil) {
					cancelStream()
					return
				}
			}
			cancelStream()
			if retryAttempt {
				continue
			}
			_ = flushBuffered()
			_ = flushTool()
			return
		}
	}
}

func (p *toolSanitizingProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	req = prepareRequest(req)
	msg, stop, usage, err := p.inner.Complete(ctx, req)
	if err != nil && isMaxTokensContextError(err) && req.MaxTokens > 1024 {
		req.MaxTokens = 1024
		msg, stop, usage, err = p.inner.Complete(ctx, req)
	}
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
