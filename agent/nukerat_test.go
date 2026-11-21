package agent

import (
	"strings"
	"testing"
	"time"
)

// ========== IOC Collector Tests ==========

func TestIOCExtractor(t *testing.T) {
	collector := NewCollector(CollectorConfig{
		AutoExtract: true,
		Tags:        []string{"test"},
	})

	text := `Scanning target 192.168.1.100 and https://admin.example.com/dashboard
Found email: admin@example.com
SHA256: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
File: C:\Windows\System32\config\SAM`

	iocs := collector.ExtractFromText(text, "test_command", nil, "session-1")
	if len(iocs) < 3 {
		t.Errorf("Expected at least 3 IOCs, got %d", len(iocs))
	}
	stats := collector.Stats()
	if stats.Total == 0 {
		t.Error("Expected non-zero stats")
	}
}

func TestIOCDeduplication(t *testing.T) {
	collector := NewCollector(CollectorConfig{AutoExtract: true})
	collector.Add(&IOC{Type: IOCIPv4, Value: "192.168.1.1", Source: "test"})
	collector.Add(&IOC{Type: IOCIPv4, Value: "192.168.1.1", Source: "test"})

	if collector.Stats().Total != 1 {
		t.Errorf("Expected 1 IOC after dedup, got %d", collector.Stats().Total)
	}
	iocs := collector.GetAll()
	if iocs[0].Count != 2 {
		t.Errorf("Expected count 2, got %d", iocs[0].Count)
	}
}

func TestIOCFiltering(t *testing.T) {
	collector := NewCollector(CollectorConfig{AutoExtract: true})
	collector.Add(&IOC{Type: IOCIPv4, Value: "10.0.0.1", Severity: "low"})
	collector.Add(&IOC{Type: IOCDomain, Value: "evil.com", Severity: "high"})

	ipv4s := collector.Get(IOCFilter{Type: IOCIPv4})
	if len(ipv4s) != 1 {
		t.Errorf("Expected 1 IPv4, got %d", len(ipv4s))
	}

	high := collector.Get(IOCFilter{Severity: "high"})
	if len(high) != 1 {
		t.Errorf("Expected 1 high severity, got %d", len(high))
	}
}

func TestIOCClear(t *testing.T) {
	collector := NewCollector(CollectorConfig{AutoExtract: true})
	collector.Add(&IOC{Type: IOCIPv4, Value: "10.0.0.1"})
	collector.Clear()
	if collector.Stats().Total != 0 {
		t.Error("Expected empty collector after clear")
	}
}

// ========== Credential Store Tests ==========

func TestCredentialStore(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	taskID := int64(1)
	id, err := store.Add(&Credential{
		Type: CredPassword, Username: "admin", Password: "SuperSecret123!",
		Domain: "EXAMPLE", Host: "192.168.1.100", Service: "rdp", TaskID: &taskID,
	})
	if err != nil {
		t.Fatalf("Failed to add credential: %v", err)
	}
	if id == 0 {
		t.Error("Expected non-zero credential ID")
	}

	cred, err := store.Get(id)
	if err != nil {
		t.Fatalf("Failed to get credential: %v", err)
	}
	if cred.Password != "SuperSecret123!" {
		t.Errorf("Password mismatch: got %s", cred.Password)
	}

	results, _ := store.Query(CredFilter{Service: "rdp"})
	if len(results) != 1 {
		t.Errorf("Query failed or wrong count: %d", len(results))
	}

	stats := store.Stats()
	if stats.Total != 1 {
		t.Errorf("Expected 1 credential in stats, got %d", stats.Total)
	}
}

func TestCredentialEncryption(t *testing.T) {
	store, _ := NewStore(StoreConfig{})
	id, _ := store.Add(&Credential{Type: CredPassword, Username: "test", Password: "plaintext-password"})
	cred, _ := store.Get(id)
	if cred.Password != "plaintext-password" {
		t.Errorf("Decryption failed: got %s", cred.Password)
	}
}

// ========== Session Manager Tests ==========

func TestSessionManager(t *testing.T) {
	mgr := NewManager(ManagerConfig{})
	hostID := mgr.RegisterHost(&HostInfo{Hostname: "TARGET-PC", IP: "192.168.1.100", OS: "Windows 11"})
	if hostID == 0 {
		t.Fatal("Failed to register host")
	}

	sess, err := mgr.CreateSession(hostID, "ADMINISTRATOR", "explorer.exe", nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	if sess.Status != SessionOnline {
		t.Errorf("Expected online status, got %s", sess.Status)
	}

	err = mgr.UpdateSessionHeartbeat(sess.ID)
	if err != nil {
		t.Fatalf("Heartbeat failed: %v", err)
	}

	retrieved := mgr.GetSession(sess.ID)
	if retrieved.NumCommands != 1 {
		t.Errorf("Expected 1 command, got %d", retrieved.NumCommands)
	}

	stats := mgr.Stats()
	if stats.Online != 1 {
		t.Errorf("Expected 1 online session, got %d", stats.Online)
	}
}

func TestSessionLifecycle(t *testing.T) {
	mgr := NewManager(ManagerConfig{})
	hostID := mgr.RegisterHost(&HostInfo{Hostname: "TEST", IP: "10.0.0.1"})
	sess, _ := mgr.CreateSession(hostID, "user", "bash", nil)

	err := mgr.CloseSession(sess.ID)
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	closed := mgr.GetSession(sess.ID)
	if closed.Status != SessionDead {
		t.Errorf("Expected dead status, got %s", closed.Status)
	}
}

// ========== Report Generator Tests ==========

func TestReportGenerationJSON(t *testing.T) {
	gen := NewGenerator(GeneratorConfig{Title: "Test Report"})
	data := FullReportData{
		Metadata: ReportMetadata{Title: "Test Pentest Report", GeneratedAt: time.Now()},
		Stats:    ReportStats{TotalActivities: 42, TotalHosts: 5, TotalIOCs: 20, TotalCredentials: 3, HighSeverityIOCs: 8},
	}
	report, err := gen.Generate(data, FormatJSON)
	if err != nil {
		t.Fatalf("JSON generation failed: %v", err)
	}
	if report.Format != FormatJSON {
		t.Error("Wrong format")
	}
	if len(report.Content) == 0 {
		t.Error("Empty content")
	}
}

func TestReportGenerationText(t *testing.T) {
	gen := NewGenerator(GeneratorConfig{})
	data := FullReportData{Metadata: ReportMetadata{Title: "Test"}, Stats: ReportStats{TotalActivities: 10, TotalHosts: 2, TotalIOCs: 5}}
	report, err := gen.Generate(data, FormatText)
	if err != nil {
		t.Fatalf("Text generation failed: %v", err)
	}
	if !strings.Contains(string(report.Content), "EXECUTIVE SUMMARY") {
		t.Error("Missing executive summary section")
	}
}

func TestReportGenerationHTML(t *testing.T) {
	gen := NewGenerator(GeneratorConfig{})
	data := FullReportData{
		Metadata: ReportMetadata{Title: "Security Assessment"},
		Stats:    ReportStats{TotalActivities: 15, TotalHosts: 3, TotalIOCs: 7, TotalCredentials: 2, HighSeverityIOCs: 3},
		Hosts:    []HostSummary{{Hostname: "WEB01", IP: "10.0.0.1", OS: "Linux", Status: "online"}},
		IOCs:     []IOCSummary{{Type: "ipv4", Value: "93.184.216.34", Severity: "medium", Count: 2}},
	}
	report, err := gen.Generate(data, FormatHTML)
	if err != nil {
		t.Fatalf("HTML generation failed: %v", err)
	}
	content := string(report.Content)
	if !strings.Contains(content, "<html") {
		t.Errorf("Invalid HTML output, length: %d", len(content))
	}
}

// ========== Armory/Tool Catalog Tests ==========

func TestArmoryRegistry(t *testing.T) {
	reg := NewRegistry(RegistryConfig{})
	stats := reg.Stats()
	if stats.Total < 10 {
		t.Errorf("Expected at least 10 built-in tools, got %d", stats.Total)
	}

	portScan := reg.GetByName("port-scan")
	if portScan == nil {
		t.Fatal("port-scan tool not found")
	}
	if portScan.Category != CatRecon {
		t.Errorf("Expected recon category, got %s", portScan.Category)
	}

	reconTools := reg.Query(ToolFilter{Category: CatRecon})
	if len(reconTools) == 0 {
		t.Error("No recon tools found")
	}

	customID, err := reg.Register(&Tool{
		Name: "custom-scanner", Type: ToolScript, Category: CatRecon,
		Description: "Custom scanner", ParseMode: ParseJSON, Tags: []string{"custom"}, Platform: "linux",
	})
	if err != nil {
		t.Fatalf("Failed to register custom tool: %v", err)
	}
	if customID == 0 {
		t.Error("Expected non-zero tool ID")
	}

	custom := reg.GetByName("custom-scanner")
	if custom == nil {
		t.Fatal("Custom tool not found after registration")
	}
}

func TestArmoryEnableDisable(t *testing.T) {
	reg := NewRegistry(RegistryConfig{})
	tool := reg.GetByName("port-scan")
	if tool == nil {
		t.Fatal("Tool not found")
	}

	err := reg.Disable(tool.ID)
	if err != nil {
		t.Fatalf("Disable failed: %v", err)
	}
	disabled := reg.Get(tool.ID)
	if disabled.Enabled {
		t.Error("Tool should be disabled")
	}

	err = reg.Enable(tool.ID)
	if err != nil {
		t.Fatalf("Enable failed: %v", err)
	}
	enabled := reg.Get(tool.ID)
	if !enabled.Enabled {
		t.Error("Tool should be enabled")
	}
}

// ========== Utility Function Tests ==========

func TestComputeFileHash(t *testing.T) {
	hash := ComputeFileHash([]byte("test content"))
	if len(hash) != 64 {
		t.Errorf("Expected 64 char hash, got %d", len(hash))
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := map[string]bool{
		"192.168.1.1": true, "10.0.0.1": true, "172.16.0.1": true,
		"127.0.0.1": true, "8.8.8.8": false, "93.184.216.34": false,
	}
	for ip, expected := range tests {
		result := isPrivateIP(ip)
		if result != expected {
			t.Errorf("isPrivateIP(%s) = %v, want %v", ip, result, expected)
		}
	}
}
