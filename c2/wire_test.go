package c2

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestEncodeDecodeNone(t *testing.T) {
	in := Beacon{ID: "c2_x", Host: "host1"}
	body, hdrs, err := encodePayload(encNone, "tok", in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if hdrs[hdrEnc] != encNone {
		t.Fatalf("enc header: %v", hdrs)
	}
	var out Beacon
	if err := decodePayload(encNone, "", "tok", body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out != in {
		t.Fatalf("roundtrip: %+v != %+v", out, in)
	}
	// Plain JSON fallback (curl-style manual checks).
	raw, _ := json.Marshal(in)
	var out2 Beacon
	if err := decodePayload(encNone, "", "tok", raw, &out2); err != nil || out2.ID != in.ID {
		t.Fatalf("plain json fallback: %v %+v", err, out2)
	}
	// Base64(JSON).
	var out3 Beacon
	if err := decodePayload(encNone, "", "tok", []byte(base64.StdEncoding.EncodeToString(raw)), &out3); err != nil || out3.ID != in.ID {
		t.Fatalf("b64 json: %v %+v", err, out3)
	}
}

func TestEncodeDecodeAES(t *testing.T) {
	in := CommandOut{Cmd: CmdShell, Args: "id; uname -a", TaskID: "7"}
	body, hdrs, err := encodePayload(encAES, "secret-token", in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if hdrs[hdrEnc] != encAES || len(hdrs[hdrIV]) != 32 {
		t.Fatalf("aes headers: %v", hdrs)
	}
	if bytes.Contains(body, []byte("uname")) {
		t.Fatal("plaintext leaked in aes body")
	}
	var out CommandOut
	if err := decodePayload(encAES, hdrs[hdrIV], "secret-token", body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out != in {
		t.Fatalf("roundtrip: %+v != %+v", out, in)
	}
	// Without the IV header (and no embedded IV) decoding must fail.
	var out2 CommandOut
	if err := decodePayload(encAES, "", "secret-token", body, &out2); err == nil {
		t.Fatal("missing IV accepted")
	}
	// Wrong token must fail.
	var out3 CommandOut
	if err := decodePayload(encAES, hdrs[hdrIV], "other-token", body, &out3); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestTaskHeaders(t *testing.T) {
	h := taskHeaders(CommandOut{Cmd: CmdShell, Args: "echo hi", TaskID: "42"})
	if h[hdrTaskID] != "42" || h[hdrTaskCmd] != CmdShell {
		t.Fatalf("headers: %v", h)
	}
	args, err := base64.StdEncoding.DecodeString(h[hdrTaskArgs])
	if err != nil || string(args) != "echo hi" {
		t.Fatalf("args header: %q %v", h[hdrTaskArgs], err)
	}
}
