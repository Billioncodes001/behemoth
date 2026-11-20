package tools

import (
	"reflect"
	"testing"
)

func TestInjectScannerProxyArgsPreventsRawIPExposure(t *testing.T) {
	px := "http://127.0.0.1:49152"

	if got := injectScannerProxyArgs("sqlmap", []string{"-u", "https://target.test?id=1", "--batch"}, px); !reflect.DeepEqual(got, []string{"-u", "https://target.test?id=1", "--batch", "--proxy=" + px}) {
		t.Fatalf("sqlmap proxy args mismatch: %v", got)
	}
	if got := injectScannerProxyArgs("nuclei", []string{"-u", "https://target.test"}, px); !reflect.DeepEqual(got, []string{"-u", "https://target.test", "-proxy", px}) {
		t.Fatalf("nuclei proxy args mismatch: %v", got)
	}
	if got := injectScannerProxyArgs("ffuf", []string{"-u", "https://target.test/FUZZ"}, px); !reflect.DeepEqual(got, []string{"-u", "https://target.test/FUZZ", "-x", px}) {
		t.Fatalf("ffuf proxy args mismatch: %v", got)
	}
	if got := injectScannerProxyArgs("gobuster", []string{"dir", "-u", "https://target.test"}, px); !reflect.DeepEqual(got, []string{"dir", "-u", "https://target.test", "--proxy", px}) {
		t.Fatalf("gobuster proxy args mismatch: %v", got)
	}
	// Nmap must strip raw SYN (-sS) and enforce TCP connect (-sT -Pn --proxies)
	if got := injectScannerProxyArgs("nmap", []string{"-sS", "-sV", "target.test"}, px); !reflect.DeepEqual(got, []string{"-sV", "target.test", "-sT", "-Pn", "--proxies", px}) {
		t.Fatalf("nmap proxy args mismatch: %v", got)
	}
}
