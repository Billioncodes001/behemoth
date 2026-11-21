package tools

import (
	"reflect"
	"testing"
)

func TestBuildArgs_BoolFlagsDoNotEmitLiterals(t *testing.T) {
	c := NewCatalog()
	tool, ok := c.Get("nmap-scan")
	if !ok {
		t.Fatal("nmap-scan missing from catalog")
	}
	// Only the required target is provided; bool switches must emit their bare
	// flags (no literal "true"/"false"), and ports must use -p.
	args, err := (&ToolExecutor{catalog: c}).buildArgs(tool, map[string]string{"target": "10.0.0.1"})
	if err != nil {
		t.Fatalf("buildArgs: %v", err)
	}
	want := []string{"10.0.0.1", "-p", "1-1000", "-sV"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("args = %v, want %v", args, want)
	}
}

func TestBuildArgs_FalseBoolFlagOmitted(t *testing.T) {
	c := NewCatalog()
	tool, _ := c.Get("nmap-scan")
	args, err := (&ToolExecutor{catalog: c}).buildArgs(tool, map[string]string{
		"target": "10.0.0.1",
		// explicit false for a flagged bool must emit nothing
		"service-detection": "false",
	})
	if err != nil {
		t.Fatalf("buildArgs: %v", err)
	}
	for _, a := range args {
		if a == "-sV" || a == "true" || a == "false" {
			t.Errorf("unexpected bool artifact in args: %v", args)
			break
		}
	}
}

func TestBuildArgs_FixedArgsAndFlags(t *testing.T) {
	c := NewCatalog()
	tool, ok := c.Get("gobuster-scan")
	if !ok {
		t.Fatal("gobuster-scan missing from catalog")
	}
	args, err := (&ToolExecutor{catalog: c}).buildArgs(tool, map[string]string{"url": "http://x.local"})
	if err != nil {
		t.Fatalf("buildArgs: %v", err)
	}
	if len(args) == 0 || args[0] != "dir" {
		t.Errorf("gobuster args must start with 'dir' subcommand, got %v", args)
	}
	joined := ""
	for _, a := range args {
		joined += a + " "
	}
	for _, want := range []string{"-u http://x.local", "-w /usr/share/wordlists/dirb/common.txt"} {
		if !contains(joined, want) {
			t.Errorf("args %q missing %q", joined, want)
		}
	}
}

func TestBuildArgs_ArgsTemplate(t *testing.T) {
	c := NewCatalog()
	tool, ok := c.Get("metasploit")
	if !ok {
		t.Fatal("metasploit missing from catalog")
	}
	args, err := (&ToolExecutor{catalog: c}).buildArgs(tool, map[string]string{
		"exploit": "exploit/windows/smb/ms17_010_eternalblue",
		"rhosts":  "10.0.0.5",
		"rport":   "445",
	})
	if err != nil {
		t.Fatalf("buildArgs: %v", err)
	}
	want := []string{"-q", "-x", "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.0.0.5; set RPORT 445; run; exit"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("args = %v, want %v", args, want)
	}
}

func TestBuildArgs_MissingRequired(t *testing.T) {
	c := NewCatalog()
	tool, _ := c.Get("nmap-scan")
	if _, err := (&ToolExecutor{catalog: c}).buildArgs(tool, map[string]string{}); err == nil {
		t.Error("expected error for missing required target")
	}
}

func TestNewToolsPresentInCatalog(t *testing.T) {
	c := NewCatalog()
	for _, id := range []string{
		"rustscan-scan", "masscan-scan", "smtp-user-enum", "onesixtyone-scan",
		"snmpwalk-enum", "impacket-secretsdump", "impacket-getnpusers",
		"bloodhound-collect", "msfvenom-payload", "aws-recon", "az-recon",
		"gcloud-recon", "pacu-recon", "trivy-scan", "grype-scan", "semgrep-scan",
	} {
		if _, ok := c.Get(id); !ok {
			t.Errorf("catalog missing new tool %q", id)
		}
	}
	if c.ByCategory("container") == nil || len(c.ByCategory("container")) != 2 {
		t.Errorf("container category should hold trivy + grype")
	}
	if len(c.ByCategory("sast")) != 1 {
		t.Errorf("sast category should hold semgrep")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
