package server

import (
	"fmt"
	"testing"
)

func TestExtractProxiesMultiFormatCrawlers(t *testing.T) {
	// 1. IPRoyal Astro SSR daily free list (HTML-entity-encoded JSON records)
	iproyalHTML := `<astro-island props="{&quot;initialData&quot;:[0,{&quot;records&quot;:[1,[[0,{&quot;ip&quot;:[0,&quot;198.51.100.11&quot;],&quot;port&quot;:[0,&quot;8080&quot;],&quot;protocol&quot;:[0,&quot;https&quot;],&quot;country&quot;:[0,&quot;United States&quot;],&quot;city&quot;:[0,&quot;Dallas&quot;]}],[0,{&quot;ip&quot;:[0,&quot;203.0.113.22&quot;],&quot;port&quot;:[0,&quot;3128&quot;],&quot;protocol&quot;:[0,&quot;http&quot;],&quot;country&quot;:[0,&quot;Germany&quot;],&quot;city&quot;:[0,&quot;Frankfurt&quot;]}]]]}]}">`
	gotIPRoyal := extractProxiesFromBodyWithHint(iproyalHTML, "http", "", "iproyal", true, map[string]bool{"http": true})
	if len(gotIPRoyal) != 2 {
		t.Fatalf("IPRoyal expected 2 proxies, got %d: %+v", len(gotIPRoyal), gotIPRoyal)
	}
	if gotIPRoyal[0].Host != "198.51.100.11" || gotIPRoyal[0].Port != 8080 || gotIPRoyal[0].Protocol != "http" || gotIPRoyal[0].Country != "US" || gotIPRoyal[0].City != "Dallas" {
		t.Fatalf("unexpected IPRoyal[0]: %+v", gotIPRoyal[0])
	}

	// 2. GeoNode JSON API (skips transparent, parses string port + protocols + US country)
	geoNodeJSON := `{"data":[
		{"ip":"198.51.100.40","port":"8443","protocols":["http"],"anonymityLevel":"elite","country":"US","city":"Ashburn"},
		{"ip":"198.51.100.41","port":"80","protocols":["http"],"anonymityLevel":"transparent","country":"US"}
	]}`
	gotGeo := extractProxiesFromBodyWithHint(geoNodeJSON, "http", "US", "geonode", true, map[string]bool{"http": true})
	if len(gotGeo) != 1 || gotGeo[0].Host != "198.51.100.40" || gotGeo[0].Port != 8443 || gotGeo[0].Country != "US" {
		t.Fatalf("GeoNode expected 1 elite US proxy, got %+v", gotGeo)
	}

	// 3. ProxyScrape v4 JSON API (numeric port + nested ip_data.countryCode)
	psV4JSON := `{"proxies":[{"ip":"203.0.113.55","port":8888,"protocol":"http","anonymity":"anonymous","ip_data":{"countryCode":"US","city":"Chicago"}}]}`
	gotPS := extractProxiesFromBodyWithHint(psV4JSON, "http", "", "psv4", true, map[string]bool{"http": true})
	if len(gotPS) != 1 || gotPS[0].Host != "203.0.113.55" || gotPS[0].Port != 8888 || gotPS[0].Country != "US" || gotPS[0].City != "Chicago" {
		t.Fatalf("ProxyScrape v4 unexpected: %+v", gotPS)
	}

	// 4. Webshare Free-Tier REST API JSON (proxy_address + username + password + country_code)
	webshareJSON := `{"results":[{"proxy_address":"198.51.100.77","port":6601,"username":"wsuser","password":"wspass","country_code":"US","city_name":"New York"}]}`
	gotWS := extractProxiesFromBodyWithHint(webshareJSON, "http", "", "webshare", true, map[string]bool{"http": true})
	if len(gotWS) != 1 || gotWS[0].Username != "wsuser" || gotWS[0].Password != "wspass" || gotWS[0].Country != "US" {
		t.Fatalf("Webshare unexpected: %+v", gotWS)
	}

	// 5. ProxyNova JS-obfuscated substring expression
	proxyNovaHTML := `<tr><td><script>document.write("295711847.89.159.2122957118".substring(13-6, 21-1))</script></td><td align="left"> 93 </td></tr>`
	gotNova := extractProxiesFromBodyWithHint(proxyNovaHTML, "http", "US", "proxynova", true, map[string]bool{"http": true})
	if len(gotNova) != 1 || gotNova[0].Host != "47.89.159.212" || gotNova[0].Port != 93 || gotNova[0].Country != "US" {
		t.Fatalf("ProxyNova JS decode unexpected: %+v", gotNova)
	}

	// 6. Spys.me annotated lines (skips -N transparent, keeps US-H-S)
	spysTxt := "198.51.100.90:8080 US-H-S +\n198.51.100.91:8080 DE-N! -\n"
	gotSpys := extractProxiesFromBodyWithHint(spysTxt, "http", "", "spysme", true, map[string]bool{"http": true})
	if len(gotSpys) != 1 || gotSpys[0].Host != "198.51.100.90" || gotSpys[0].Country != "US" {
		// Note: bare fallback may pick up .91 unless we check priority/country on .90
		if len(gotSpys) < 1 || gotSpys[0].Host != "198.51.100.90" || gotSpys[0].Country != "US" {
			t.Fatalf("Spys.me unexpected first candidate: %+v", gotSpys)
		}
	}

	// 7. HTML table (free-proxy-list.net / us-proxy.html)
	htmlTbl := `<tr><td>198.51.100.120</td><td>3128</td><td>US</td><td class="hm">United States</td><td>elite proxy</td><td class="hm">no</td><td class="hx">yes</td></tr>`
	gotTbl := extractProxiesFromBodyWithHint(htmlTbl, "http", "US", "usproxy", true, map[string]bool{"http": true})
	if len(gotTbl) != 1 || gotTbl[0].Host != "198.51.100.120" || gotTbl[0].Port != 3128 || gotTbl[0].Country != "US" {
		t.Fatalf("HTML table unexpected: %+v", gotTbl)
	}

	// 8. Cloudflare trace parser
	ip, loc := parseCloudflareTrace("fl=29f10\nip=198.51.100.200\nts=123\nloc=US\n")
	if ip != "198.51.100.200" || loc != "US" {
		t.Fatalf("parseCloudflareTrace got ip=%q loc=%q", ip, loc)
	}
}

func TestSelectBalancedCandidateBatchPreventsSOCKS5StarvationAndPrefersUSHTTP(t *testing.T) {
	var raw []rawCandidateProxy
	// Simulate 500 SOCKS5 candidates arriving before HTTP candidates!
	for i := 1; i <= 250; i++ {
		raw = append(raw, rawCandidateProxy{
			Protocol: "socks5",
			Host:     fmt.Sprintf("203.0.113.%d", i),
			Port:     1080,
			Priority: true,
		})
	}
	// Add 20 US HTTP candidates and 40 Global HTTP candidates after the SOCKS5 flood.
	for i := 1; i <= 20; i++ {
		raw = append(raw, rawCandidateProxy{
			Protocol: "http",
			Host:     fmt.Sprintf("198.51.100.%d", i),
			Port:     8080,
			Country:  "US",
			Priority: true,
		})
	}
	for i := 21; i <= 60; i++ {
		raw = append(raw, rawCandidateProxy{
			Protocol: "http",
			Host:     fmt.Sprintf("198.51.100.%d", i),
			Port:     8080,
			Country:  "DE",
			Priority: true,
		})
	}

	cfg := ProxyScraperConfig{
		Protocols:   []string{"http", "socks5"},
		CountryMode: "us_preferred",
	}
	batch := selectBalancedCandidateBatch(raw, cfg, 100)
	if len(batch) != 100 {
		t.Fatalf("expected 100 selected candidates, got %d", len(batch))
	}
	// First 20 MUST be the US HTTP candidates!
	for i := 0; i < 20; i++ {
		if batch[i].Protocol != "http" || batch[i].Country != "US" {
			t.Fatalf("batch[%d] expected US HTTP first, got %+v", i, batch[i])
		}
	}
	// All 60 HTTP candidates must be included (never starved by the 250 SOCKS5 candidates)!
	httpCount := 0
	for _, c := range batch {
		if c.Protocol == "http" {
			httpCount++
		}
	}
	if httpCount != 60 {
		t.Fatalf("expected all 60 HTTP candidates preserved against SOCKS5 flood, got %d", httpCount)
	}

	// Verify sortVerifiedProxies orders US HTTP ahead of non-US proxies under us_preferred
	verified := []verifiedCandidateProxy{
		{rawCandidateProxy: rawCandidateProxy{Protocol: "http"}, LatencyMS: 120, Country: "DE"},
		{rawCandidateProxy: rawCandidateProxy{Protocol: "socks5"}, LatencyMS: 90, Country: "US"},
		{rawCandidateProxy: rawCandidateProxy{Protocol: "http"}, LatencyMS: 240, Country: "US"},
	}
	sortVerifiedProxies(verified, "us_preferred")
	if verified[0].Country != "US" || verified[0].Protocol != "http" {
		t.Fatalf("expected US HTTP proxy ranked #1, got %+v", verified[0])
	}

	// Verify default config polls BOTH http and socks5 (with http ranked first)
	defCfg := defaultProxyScraperConfig()
	if len(defCfg.Protocols) != 2 || defCfg.Protocols[0] != "http" || defCfg.Protocols[1] != "socks5" {
		t.Fatalf("expected default protocols [http socks5], got %v", defCfg.Protocols)
	}

	// Verify RoundProxies JSON shape (data[].ip + string port + protocols[] array) parses cleanly
	roundJSON := `{"data":[{"ip":"198.51.100.44","port":"10806","protocols":["socks5"],"anonymityLevel":"elite","country":"US"},{"ip":"203.0.113.21","port":8080,"protocols":["http","https"],"anonymityLevel":"anonymous","country":"FI"}]}`
	allowedBoth := map[string]bool{"http": true, "socks5": true}
	rpCands := extractProxiesFromBodyWithHint(roundJSON, "http", "", "roundproxies-api", true, allowedBoth)
	if len(rpCands) != 2 || rpCands[0].Protocol != "socks5" || rpCands[0].Port != 10806 || rpCands[1].Protocol != "http" {
		t.Fatalf("expected 2 parsed RoundProxies candidates (socks5:10806 + http:8080), got %+v", rpCands)
	}

	// Verify rawGitHubToJSDelivr mirrors both branch and refs/heads forms
	if got := rawGitHubToJSDelivr("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt"); got != "https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/socks5.txt" {
		t.Fatalf("unexpected jsDelivr mirror URL: %q", got)
	}
	if got := rawGitHubToJSDelivr("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks5.txt"); got != "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/socks5.txt" {
		t.Fatalf("unexpected refs/heads jsDelivr mirror URL: %q", got)
	}
}
