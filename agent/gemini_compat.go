package agent

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

const (
	maxCachedThoughtSignatures = 4096
	geminiSkipSignatureJSON    = `{"google":{"thought_signature":"skip_thought_signature_validator"}}`
)

type thoughtSignatureStore struct {
	mu    sync.RWMutex
	items map[string]json.RawMessage
	order []string
}

var globalThoughtSignatures = &thoughtSignatureStore{
	items: make(map[string]json.RawMessage, 256),
}

func (s *thoughtSignatureStore) put(toolCallID string, extra json.RawMessage) {
	toolCallID = strings.TrimSpace(toolCallID)
	trimmed := bytes.TrimSpace(extra)
	if toolCallID == "" || len(trimmed) <= 2 || bytes.Equal(trimmed, []byte("null")) {
		return
	}
	cp := make(json.RawMessage, len(trimmed))
	copy(cp, trimmed)

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.items[toolCallID]; !exists {
		if len(s.order) >= maxCachedThoughtSignatures {
			evict := s.order[0]
			s.order = s.order[1:]
			delete(s.items, evict)
		}
		s.order = append(s.order, toolCallID)
	}
	s.items[toolCallID] = cp
}

func (s *thoughtSignatureStore) get(toolCallID string) (json.RawMessage, bool) {
	toolCallID = strings.TrimSpace(toolCallID)
	if toolCallID == "" {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.items[toolCallID]
	return v, ok
}

func isGoogleGeminiURL(u *url.URL) bool {
	if u == nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, "generativelanguage.googleapis.com") {
		return true
	}
	if strings.HasSuffix(host, "googleapis.com") && strings.Contains(strings.ToLower(u.Path), "/openai") {
		return true
	}
	return false
}

func isGemini3Or4Model(model string) bool {
	m := strings.ToLower(strings.TrimSpace(model))
	return strings.Contains(m, "gemini-3") || strings.Contains(m, "gemini-4")
}

// openAICompatTransport bridges provider-specific Chat Completions extensions
// (such as Google Gemini 3/4 thought_signature replay on tool_calls, thought
// summary routing, safety_settings, and strict Protobuf field rules) transparently
// at the HTTP layer without requiring SDK forks.
type openAICompatTransport struct {
	base http.RoundTripper
}

func (t openAICompatTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if req.Method != http.MethodPost || req.Body == nil || !strings.HasSuffix(strings.TrimRight(req.URL.Path, "/"), "/chat/completions") {
		return base.RoundTrip(req)
	}

	origBody, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, err
	}

	isGemini := isGoogleGeminiURL(req.URL)
	rewritten, fallbackNoExtraBody, injectedExtraBody := rewriteOutboundChatCompletions(origBody, isGemini)

	sendOnce := func(bodyBytes []byte) (*http.Response, error) {
		clone := req.Clone(req.Context())
		clone.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		clone.ContentLength = int64(len(bodyBytes))
		clone.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
		return base.RoundTrip(clone)
	}

	resp, err := sendOnce(rewritten)
	if err != nil {
		return nil, err
	}

	// Defensive fallback: if a Gemini-compatible proxy rejects extra_body with HTTP 400,
	// immediately retry once without extra_body while keeping tool_calls thought_signature intact.
	if injectedExtraBody && resp.StatusCode == http.StatusBadRequest && len(fallbackNoExtraBody) > 0 {
		errBytes, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		lowerErr := strings.ToLower(string(errBytes))
		if strings.Contains(lowerErr, "extra_body") || strings.Contains(lowerErr, "safety_settings") || strings.Contains(lowerErr, "thinking_config") {
			resp, err = sendOnce(fallbackNoExtraBody)
			if err != nil {
				return nil, err
			}
		} else {
			resp.Body = io.NopCloser(bytes.NewReader(errBytes))
			resp.ContentLength = int64(len(errBytes))
		}
	}

	if resp.StatusCode != http.StatusOK || resp.Body == nil {
		return resp, nil
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "text/event-stream") {
		resp.Body = newSSECompatReader(resp.Body)
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
		return resp, nil
	}
	if strings.Contains(ct, "application/json") {
		rawResp, rerr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if rerr != nil {
			return nil, rerr
		}
		transformed := transformOpenAIJSONResponse(rawResp)
		resp.Body = io.NopCloser(bytes.NewReader(transformed))
		resp.ContentLength = int64(len(transformed))
		resp.Header.Set("Content-Length", strconv.Itoa(len(transformed)))
	}
	return resp, nil
}

func rewriteOutboundChatCompletions(orig []byte, isGeminiEndpoint bool) (rewritten []byte, withoutExtraBody []byte, injectedExtra bool) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(orig, &root); err != nil || root == nil {
		return orig, nil, false
	}

	var modelStr string
	if rawModel, ok := root["model"]; ok {
		_ = json.Unmarshal(rawModel, &modelStr)
	}
	needsGeminiSig := isGeminiEndpoint || isGemini3Or4Model(modelStr)

	var thinkingObj struct {
		Type string `json:"type"`
	}
	if rawThink, ok := root["thinking"]; ok {
		_ = json.Unmarshal(rawThink, &thinkingObj)
	}

	modified := false
	if rawMsgs, ok := root["messages"]; ok {
		var msgs []map[string]json.RawMessage
		if json.Unmarshal(rawMsgs, &msgs) == nil {
			msgsChanged := false
			for i := range msgs {
				var role string
				_ = json.Unmarshal(msgs[i]["role"], &role)
				if role != "assistant" {
					continue
				}
				if isGeminiEndpoint {
					if _, hasRC := msgs[i]["reasoning_content"]; hasRC {
						delete(msgs[i], "reasoning_content")
						msgsChanged = true
					}
				}
				rawTCs, hasTCs := msgs[i]["tool_calls"]
				if !hasTCs {
					continue
				}
				var tcs []map[string]json.RawMessage
				if json.Unmarshal(rawTCs, &tcs) != nil || len(tcs) == 0 {
					continue
				}
				tcChanged := false
				for j := range tcs {
					if existing, ok := tcs[j]["extra_content"]; ok && len(bytes.TrimSpace(existing)) > 2 {
						continue
					}
					var tcID string
					_ = json.Unmarshal(tcs[j]["id"], &tcID)
					if sig, ok := globalThoughtSignatures.get(tcID); ok {
						tcs[j]["extra_content"] = sig
						tcChanged = true
					} else if needsGeminiSig && j == 0 {
						tcs[j]["extra_content"] = json.RawMessage(geminiSkipSignatureJSON)
						tcChanged = true
					}
				}
				if tcChanged {
					if encTCs, err := json.Marshal(tcs); err == nil {
						msgs[i]["tool_calls"] = encTCs
						msgsChanged = true
					}
				}
			}
			if msgsChanged {
				if encMsgs, err := json.Marshal(msgs); err == nil {
					root["messages"] = encMsgs
					modified = true
				}
			}
		}
	}

	if isGeminiEndpoint {
		if _, hasThinking := root["thinking"]; hasThinking {
			delete(root, "thinking")
			modified = true
		}
	}

	var baseBytes []byte
	if modified {
		if b, err := json.Marshal(root); err == nil {
			baseBytes = b
		} else {
			baseBytes = orig
		}
	} else {
		baseBytes = orig
	}

	if isGeminiEndpoint {
		if _, hasExtra := root["extra_body"]; !hasExtra {
			googleCfg := map[string]any{
				"safety_settings": []map[string]string{
					{"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
					{"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
					{"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
					{"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
				},
			}
			if !strings.EqualFold(thinkingObj.Type, "disabled") {
				googleCfg["thinking_config"] = map[string]any{
					"include_thoughts": true,
				}
			}
			if extraRaw, err := json.Marshal(map[string]any{"google": googleCfg}); err == nil {
				root["extra_body"] = extraRaw
				if withExtra, err := json.Marshal(root); err == nil {
					return withExtra, baseBytes, true
				}
			}
		}
	}

	return baseBytes, nil, false
}

func isSafetyFinishReason(r string) bool {
	switch strings.ToUpper(strings.TrimSpace(r)) {
	case "CONTENT_FILTER", "SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST", "RECITATION", "SPII", "IMAGE_SAFETY":
		return true
	}
	return false
}

func extraContentMarksThought(extra json.RawMessage) bool {
	if len(bytes.TrimSpace(extra)) <= 2 {
		return false
	}
	var parsed struct {
		Thought bool `json:"thought"`
		Google  struct {
			Thought bool `json:"thought"`
		} `json:"google"`
	}
	if json.Unmarshal(extra, &parsed) != nil {
		return false
	}
	return parsed.Thought || parsed.Google.Thought
}

func captureToolCallsExtraContent(rawTCs json.RawMessage, idxToID map[int]string) {
	if len(bytes.TrimSpace(rawTCs)) <= 2 {
		return
	}
	var tcs []struct {
		ID           string          `json:"id"`
		Index        int             `json:"index"`
		ExtraContent json.RawMessage `json:"extra_content"`
	}
	if json.Unmarshal(rawTCs, &tcs) != nil {
		return
	}
	for _, tc := range tcs {
		id := strings.TrimSpace(tc.ID)
		if id != "" && idxToID != nil {
			idxToID[tc.Index] = id
		} else if id == "" && idxToID != nil {
			id = idxToID[tc.Index]
		}
		if id != "" && len(bytes.TrimSpace(tc.ExtraContent)) > 2 {
			globalThoughtSignatures.put(id, tc.ExtraContent)
		}
	}
}

func transformOpenAISSEData(data string, idxToID map[int]string) string {
	trimmed := strings.TrimSpace(data)
	if trimmed == "" || trimmed == "[DONE]" || trimmed[0] != '{' {
		return data
	}

	var frame map[string]json.RawMessage
	if json.Unmarshal([]byte(trimmed), &frame) != nil {
		return data
	}

	var choices []map[string]json.RawMessage
	hasChoices := false
	if rawChoices, ok := frame["choices"]; ok {
		if json.Unmarshal(rawChoices, &choices) == nil {
			hasChoices = true
		}
	}

	// If Gemini blocked at the prompt level with choices: [], surface finish_reason: "content_filter"
	if (!hasChoices || len(choices) == 0) && frame["promptFeedback"] != nil {
		var pf struct {
			BlockReason string `json:"blockReason"`
		}
		if json.Unmarshal(frame["promptFeedback"], &pf) == nil && pf.BlockReason != "" {
			frame["choices"] = json.RawMessage(`[{"index":0,"delta":{},"finish_reason":"content_filter"}]`)
			if out, err := json.Marshal(frame); err == nil {
				return string(out)
			}
		}
		return data
	}

	changed := false
	for i := range choices {
		if rawFR, ok := choices[i]["finish_reason"]; ok {
			var fr string
			if json.Unmarshal(rawFR, &fr) == nil && fr != "" {
				if isSafetyFinishReason(fr) && fr != "content_filter" {
					choices[i]["finish_reason"] = json.RawMessage(`"content_filter"`)
					changed = true
				} else if strings.EqualFold(fr, "MALFORMED_FUNCTION_CALL") {
					choices[i]["finish_reason"] = json.RawMessage(`"malformed_function_call"`)
					changed = true
				}
			}
		}

		rawDelta, ok := choices[i]["delta"]
		if !ok {
			continue
		}
		var delta map[string]json.RawMessage
		if json.Unmarshal(rawDelta, &delta) != nil {
			continue
		}

		if rawTCs, hasTCs := delta["tool_calls"]; hasTCs {
			captureToolCallsExtraContent(rawTCs, idxToID)
		}

		// Gemini streams thought summaries as delta.content with delta.extra_content.google.thought = true.
		// Move them into delta.reasoning_content so the SDK renders them in the minimized Thinking block
		// instead of leaking reasoning text into the assistant's reply.
		if extraContentMarksThought(delta["extra_content"]) {
			var contentStr string
			if rawContent, hasContent := delta["content"]; hasContent && json.Unmarshal(rawContent, &contentStr) == nil && contentStr != "" {
				delta["reasoning_content"] = rawContent
				delete(delta, "content")
				if encDelta, err := json.Marshal(delta); err == nil {
					choices[i]["delta"] = encDelta
					changed = true
				}
			}
		}
	}

	if !changed {
		return data
	}
	if encChoices, err := json.Marshal(choices); err == nil {
		frame["choices"] = encChoices
		if out, err := json.Marshal(frame); err == nil {
			return string(out)
		}
	}
	return data
}

func transformOpenAIJSONResponse(raw []byte) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return raw
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(trimmed, &root) != nil {
		return raw
	}
	var choices []map[string]json.RawMessage
	hasChoices := false
	if rawChoices, ok := root["choices"]; ok && json.Unmarshal(rawChoices, &choices) == nil {
		hasChoices = true
	}
	if (!hasChoices || len(choices) == 0) && root["promptFeedback"] != nil {
		var pf struct {
			BlockReason string `json:"blockReason"`
		}
		if json.Unmarshal(root["promptFeedback"], &pf) == nil && pf.BlockReason != "" {
			root["choices"] = json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":""},"finish_reason":"content_filter"}]`)
			if out, err := json.Marshal(root); err == nil {
				return out
			}
		}
		return raw
	}

	changed := false
	for i := range choices {
		if rawFR, ok := choices[i]["finish_reason"]; ok {
			var fr string
			if json.Unmarshal(rawFR, &fr) == nil && fr != "" && isSafetyFinishReason(fr) && fr != "content_filter" {
				choices[i]["finish_reason"] = json.RawMessage(`"content_filter"`)
				changed = true
			}
		}
		if rawMsg, ok := choices[i]["message"]; ok {
			var msg map[string]json.RawMessage
			if json.Unmarshal(rawMsg, &msg) == nil {
				if rawTCs, hasTCs := msg["tool_calls"]; hasTCs {
					captureToolCallsExtraContent(rawTCs, nil)
				}
				if extraContentMarksThought(msg["extra_content"]) {
					var contentStr string
					if rawContent, hasContent := msg["content"]; hasContent && json.Unmarshal(rawContent, &contentStr) == nil && contentStr != "" {
						msg["reasoning_content"] = rawContent
						delete(msg, "content")
						if encMsg, err := json.Marshal(msg); err == nil {
							choices[i]["message"] = encMsg
							changed = true
						}
					}
				}
			}
		}
	}
	if !changed {
		return raw
	}
	if encChoices, err := json.Marshal(choices); err == nil {
		root["choices"] = encChoices
		if out, err := json.Marshal(root); err == nil {
			return out
		}
	}
	return raw
}

type sseCompatReader struct {
	closer  io.Closer
	br      *bufio.Reader
	outBuf  bytes.Buffer
	idxToID map[int]string
	eof     bool
}

func newSSECompatReader(rc io.ReadCloser) *sseCompatReader {
	return &sseCompatReader{
		closer:  rc,
		br:      bufio.NewReaderSize(rc, 64*1024),
		idxToID: make(map[int]string),
	}
}

func (s *sseCompatReader) Read(p []byte) (int, error) {
	for s.outBuf.Len() == 0 {
		if s.eof {
			return 0, io.EOF
		}
		line, err := s.br.ReadString('\n')
		if len(line) > 0 {
			trimmedRight := strings.TrimRight(line, "\r\n")
			suffix := line[len(trimmedRight):]
			if suffix == "" {
				suffix = "\n"
			}
			if strings.HasPrefix(trimmedRight, "data:") {
				payload := strings.TrimPrefix(trimmedRight[len("data:"):], " ")
				rewritten := transformOpenAISSEData(payload, s.idxToID)
				s.outBuf.WriteString("data: ")
				s.outBuf.WriteString(rewritten)
				s.outBuf.WriteString(suffix)
			} else {
				s.outBuf.WriteString(line)
			}
		}
		if err != nil {
			if err == io.EOF {
				s.eof = true
				if s.outBuf.Len() > 0 {
					break
				}
			}
			return 0, err
		}
	}
	return s.outBuf.Read(p)
}

func (s *sseCompatReader) Close() error {
	return s.closer.Close()
}
