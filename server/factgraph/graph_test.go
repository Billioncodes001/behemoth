package factgraph

import (
	"testing"
)

func TestNewFact(t *testing.T) {
	f := NewFact(FactHost, "192.168.1.1", "Test host")

	if f.ID == "" {
		t.Error("Fact ID is empty")
	}
	if f.Kind != FactHost {
		t.Errorf("Kind = %s, want %s", f.Kind, FactHost)
	}
	if f.Title != "192.168.1.1" {
		t.Errorf("Title = %s, want 192.168.1.1", f.Title)
	}
	if !f.Active {
		t.Error("New fact should be active by default")
	}
	if f.Verified {
		t.Error("New fact should not be verified by default")
	}
}

func TestHostFact(t *testing.T) {
	f := HostFact("10.0.0.1", "webserver.local", []string{"80", "443"})

	if f.Kind != FactHost {
		t.Errorf("Kind = %s, want host", f.Kind)
	}
	if f.Metadata["ip"] != "10.0.0.1" {
		t.Errorf("Metadata[ip] = %s, want 10.0.0.1", f.Metadata["ip"])
	}
	if f.Metadata["ports"] != "80,443" {
		t.Errorf("Metadata[ports] = %s, want 80,443", f.Metadata["ports"])
	}
}

func TestServiceFact(t *testing.T) {
	f := ServiceFact("10.0.0.1", "80", "tcp", "http")

	if f.Kind != FactService {
		t.Errorf("Kind = %s, want service", f.Kind)
	}
	if f.Metadata["service"] != "http" {
		t.Errorf("Metadata[service] = %s, want http", f.Metadata["service"])
	}
}

func TestCredFact(t *testing.T) {
	f := CredFact("admin", "password123", "ssh")

	if f.Kind != FactCred {
		t.Errorf("Kind = %s, want credential", f.Kind)
	}
	if f.Confidence < 0.7 {
		t.Errorf("Confidence should be high for credentials, got %f", f.Confidence)
	}
	// Password should be masked in title
	if f.Content == "password123" {
		t.Error("Password should be masked in content")
	}
}

func TestVulnFact(t *testing.T) {
	f := VulnFact("SQL Injection", "high", "SQLi in login form", "CVE-2024-1234")

	if f.Kind != FactVuln {
		t.Errorf("Kind = %s, want vulnerability", f.Kind)
	}
	if f.Metadata["severity"] != "high" {
		t.Errorf("Severity = %s, want high", f.Metadata["severity"])
	}
	if f.Metadata["cve_id"] != "CVE-2024-1234" {
		t.Errorf("CVE ID = %s, want CVE-2024-1234", f.Metadata["cve_id"])
	}
}

func TestFlagFact(t *testing.T) {
	f := FlagFact("CTF{test_flag}", "Web Challenge", "web")

	if f.Kind != FactFlag {
		t.Errorf("Kind = %s, want flag", f.Kind)
	}
	if !f.Verified {
		t.Error("Flags should be auto-verified")
	}
	if f.Confidence != 1.0 {
		t.Errorf("Flag confidence should be 1.0, got %f", f.Confidence)
	}
}

func TestGraph_AddAndGet(t *testing.T) {
	g := NewGraph()
	f := NewFact(FactHost, "192.168.1.1", "Target server")

	g.Add(f)

	if g.Count() != 1 {
		t.Errorf("Count() = %d, want 1", g.Count())
	}

	retrieved, ok := g.Get(f.ID)
	if !ok {
		t.Fatal("Get() returned false for existing fact")
	}
	if retrieved.Title != "192.168.1.1" {
		t.Errorf("Title = %s, want 192.168.1.1", retrieved.Title)
	}
}

func TestGraph_Remove(t *testing.T) {
	g := NewGraph()
	f := NewFact(FactHost, "192.168.1.1", "Target")
	g.Add(f)

	g.Remove(f.ID)

	if g.Count() != 0 {
		t.Errorf("Count() after remove = %d, want 0", g.Count())
	}
	_, ok := g.Get(f.ID)
	if ok {
		t.Error("Get() after remove should return false")
	}
}

func TestGraph_Update(t *testing.T) {
	g := NewGraph()
	f := NewFact(FactHost, "192.168.1.1", "Original")
	g.Add(f)

	err := g.Update(f.ID, func(fact *Fact) {
		fact.Title = "Updated Title"
		fact.Confidence = 0.9
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	updated, _ := g.Get(f.ID)
	if updated.Title != "Updated Title" {
		t.Errorf("Title after update = %s, want 'Updated Title'", updated.Title)
	}
	if updated.Confidence != 0.9 {
		t.Errorf("Confidence after update = %f, want 0.9", updated.Confidence)
	}
}

func TestGraph_Link(t *testing.T) {
	g := NewGraph()
	host := HostFact("10.0.0.1", "target", []string{"80"})
	svc := ServiceFact("10.0.0.1", "80", "tcp", "http")

	g.Add(host)
	g.Add(svc)

	err := g.Link(host.ID, svc.ID)
	if err != nil {
		t.Fatalf("Link() error = %v", err)
	}

	// Check derived IDs
	hostUpdated, _ := g.Get(host.ID)
	found := false
	for _, id := range hostUpdated.DerivedIDs {
		if id == svc.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Host fact should have service in DerivedIDs")
	}
}

func TestGraph_Search(t *testing.T) {
	g := NewGraph()
	g.Add(NewFact(FactHost, "192.168.1.1", "Web server"))
	g.Add(NewFact(FactVuln, "XSS", "Cross-site scripting"))
	g.Add(NewFact(FactService, "HTTP/80", "Apache web server"))

	results := g.Search("web")
	if len(results) == 0 {
		t.Error("Search('web') should return results")
	}

	results = g.Search("nonexistent")
	if len(results) > 0 {
		t.Error("Search('nonexistent') should return no results")
	}
}

func TestGraph_Stats(t *testing.T) {
	g := NewGraph()
	g.Add(NewFact(FactHost, "10.0.0.1", "Host"))
	g.Add(NewFact(FactService, "80/tcp", "HTTP"))
	g.Add(NewFact(FactVuln, "XSS", "XSS vuln"))

	stats := g.Stats()
	if stats["total"] != 3 {
		t.Errorf("Stats[total] = %d, want 3", stats["total"])
	}
	if stats["host"] != 1 {
		t.Errorf("Stats[host] = %d, want 1", stats["host"])
	}
}

func TestGraph_ByKind(t *testing.T) {
	g := NewGraph()
	g.Add(NewFact(FactHost, "10.0.0.1", "H1"))
	g.Add(NewFact(FactHost, "10.0.0.2", "H2"))
	g.Add(NewFact(FactVuln, "XSS", "XSS"))

	hosts := g.ByKind(FactHost)
	if len(hosts) != 2 {
		t.Errorf("ByKind(host) = %d, want 2", len(hosts))
	}

	vulns := g.ByKind(FactVuln)
	if len(vulns) != 1 {
		t.Errorf("ByKind(vulnerability) = %d, want 1", len(vulns))
	}
}
