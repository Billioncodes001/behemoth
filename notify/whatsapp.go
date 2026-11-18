package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const whatsappTextLimit = 4096
const whatsappReservedRunes = 160

// whatsappChannel implements WhatsApp notifications via Meta WhatsApp Business Cloud API
// (graph.facebook.com) or a self-hosted / gateway WhatsApp HTTP endpoint (WAHA, Evolution API, etc.).
type whatsappChannel struct{}

func (whatsappChannel) Kind() string { return KindWhatsApp }

func (whatsappChannel) DefaultRatePerMin() int { return 30 }

func (whatsappChannel) SecretKeys() []string { return []string{"access_token"} }

func (whatsappChannel) DestinationKeys() []string { return []string{"api_url", "phone_number_id"} }

func (whatsappChannel) Validate(cfg map[string]any) error {
	if cfgString(cfg, "access_token") == "" {
		return errors.New("缺少 Access Token")
	}
	if len(whatsappRecipients(cfg)) == 0 {
		return errors.New("缺少收件人号码 (To)")
	}
	phoneID := cfgString(cfg, "phone_number_id")
	apiURL := cfgString(cfg, "api_url")
	if phoneID == "" && apiURL == "" {
		return errors.New("缺少 Phone Number ID 或网关 API 地址")
	}
	if apiURL != "" {
		if err := validateHTTPURL(apiURL); err != nil {
			return fmt.Errorf("API 地址无效: %w", err)
		}
	}
	return nil
}

func whatsappRecipients(cfg map[string]any) []string {
	if list := cfgStrings(cfg, "to"); len(list) > 0 {
		var out []string
		for _, item := range list {
			for _, part := range strings.FieldsFunc(item, func(r rune) bool {
				return r == ',' || r == '，' || r == ';' || r == ' ' || r == '\n'
			}) {
				if p := strings.TrimSpace(part); p != "" {
					out = append(out, p)
				}
			}
		}
		return out
	}
	return nil
}

func (c whatsappChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	endpoint, isCloudAPI, err := whatsappEndpoint(cfg)
	if err != nil {
		return 0, Permanent(err)
	}
	text, kept := whatsappText(m)
	token := cfgString(cfg, "access_token")
	headers := map[string]string{
		"Authorization": "Bearer " + token,
	}
	recipients := whatsappRecipients(cfg)
	for _, recipient := range recipients {
		var payload map[string]any
		if isCloudAPI {
			payload = map[string]any{
				"messaging_product": "whatsapp",
				"recipient_type":    "individual",
				"to":                recipient,
				"type":              "text",
				"text": map[string]any{
					"preview_url": true,
					"body":        text,
				},
			}
		} else {
			payload = map[string]any{
				"messaging_product": "whatsapp",
				"to":                recipient,
				"chatId":            recipient,
				"phone":             recipient,
				"type":              "text",
				"text": map[string]any{
					"preview_url": true,
					"body":        text,
				},
				"body":    text,
				"message": text,
			}
		}
		raw, err := doJSON(ctx, "POST", endpoint, headers, payload)
		if err != nil {
			return 0, err
		}
		var errResp struct {
			Error *struct {
				Message string `json:"message"`
				Type    string `json:"type"`
				Code    int    `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &errResp) == nil && errResp.Error != nil && errResp.Error.Message != "" {
			if errResp.Error.Code == 4 || errResp.Error.Code == 80007 || errResp.Error.Code == 130429 {
				return 0, fmt.Errorf("WhatsApp 限流 (%d): %s", errResp.Error.Code, errResp.Error.Message)
			}
			return 0, Permanent(fmt.Errorf("WhatsApp 返回错误 %d: %s", errResp.Error.Code, errResp.Error.Message))
		}
	}
	return kept, nil
}

func whatsappEndpoint(cfg map[string]any) (string, bool, error) {
	phoneID := cfgString(cfg, "phone_number_id")
	base := strings.TrimSuffix(cfgString(cfg, "api_url"), "/")
	if phoneID != "" {
		if base == "" {
			base = "https://graph.facebook.com/v21.0"
		}
		raw := base + "/" + url.PathEscape(phoneID) + "/messages"
		u, err := url.Parse(raw)
		if err != nil {
			return "", true, fmt.Errorf("拼接 WhatsApp API 地址失败（API 地址：%s）", redactRequestTarget(base))
		}
		return u.String(), true, nil
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", false, fmt.Errorf("拼接 WhatsApp API 地址失败（API 地址：%s）", redactRequestTarget(base))
	}
	return u.String(), false, nil
}

func whatsappText(m Message) (string, int) {
	var b strings.Builder
	b.WriteString("*" + whatsappEscape(markdownTitle(m)) + "*\n")
	if m.Batch {
		footer := ""
		if m.HomeURL != "" {
			footer = fmt.Sprintf("\n\n在平台中查看全部: %s", m.HomeURL)
		}
		kept := packItemCount(m.Items, whatsappTextLimit, whatsappReservedRunes, footer, runeSize, func(it Item, idx int) string {
			return telegramBatchLine(it, idx+1)
		})
		items := m.Items[:kept]
		b.Reset()
		b.WriteString("*" + whatsappEscape(telegramBatchTitle(m, items, len(m.Items))) + "*")
		for i, it := range items {
			b.WriteString("\n" + whatsappEscape(telegramBatchLine(it, i+1)))
		}
		b.WriteString(footer)
		return TruncateRunes(b.String(), whatsappTextLimit), kept
	}
	if len(m.Items) == 0 {
		return b.String(), 0
	}
	it := m.Items[0]
	if it.IsStatusChange() {
		b.WriteString(fmt.Sprintf("\n*状态变更*：%s → %s",
			whatsappEscape(StatusLabel(it.FromStatus)), whatsappEscape(StatusLabel(it.ToStatus))))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		b.WriteString("\n*类型*：" + whatsappEscape(it.VulnClass))
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		b.WriteString("\n*资产*：" + whatsappEscape(a))
	}
	if s := OneLine(it.Summary, maxSummaryRunes); s != "" {
		b.WriteString("\n*摘要*：" + whatsappEscape(s))
	}
	if it.DetailURL != "" {
		b.WriteString("\n\n查看详情: " + it.DetailURL)
	}
	return TruncateRunes(b.String(), whatsappTextLimit), 1
}

func whatsappEscape(s string) string {
	s = strings.ReplaceAll(s, "*", "＊")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}
