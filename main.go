package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	customDNS  = "46.245.69.222:53"
	publicDNS  = "8.8.8.8:53"
	proxyIP    = "176.65.243.214" // Iranian reverse proxy
	vpsIP      = "188.40.147.153" // Germany VPS
	timeout    = 8 * time.Second
	maxWorkers = 15
)

// ── Domain lists ──────────────────────────────────────────────

var testDomains = map[string][]string{
	"Discord": {
		"discord.com",
		"cdn.discordapp.com",
		"gateway.discord.gg",
		"media.discordapp.net",
	},
	"Twitch": {
		"twitch.tv",
		"www.twitch.tv",
		"gql.twitch.tv",
		"static.twitchcdn.net",
	},
	"Battle.net (Warzone)": {
		"battle.net",
		"us.battle.net",
		"account.battle.net",
		"oauth.battle.net",
	},
	"Steam": {
		"store.steampowered.com",
		"steamcommunity.com",
		"api.steampowered.com",
	},
	"Epic Games": {
		"epicgames.com",
		"www.epicgames.com",
	},
	"Riot (LoL/Valorant)": {
		"auth.riotgames.com",
		"riot-client.dyn.riotcdn.net",
	},
	"EA": {
		"accounts.ea.com",
		"signin.ea.com",
	},
	"Xbox Live": {
		"login.live.com",
		"accounts.xboxlive.com",
	},
	"Spotify": {
		"open.spotify.com",
		"accounts.spotify.com",
	},
	"ChatGPT": {
		"chatgpt.com",
		"auth.openai.com",
	},
	"Claude AI": {
		"claude.ai",
		"api.anthropic.com",
	},
	"Nvidia": {
		"www.nvidia.com",
		"login.nvidia.com",
	},
	"Google AI": {
		"gemini.google.com",
		"aistudio.google.com",
	},
}

// ── Result types ──────────────────────────────────────────────

type DNSResult struct {
	Domain       string `json:"domain"`
	CustomDNSIP  string `json:"custom_dns_ip"`
	PublicDNSIP  string `json:"public_dns_ip"`
	SystemDNSIP  string `json:"system_dns_ip"`
	IsPoisoned   bool   `json:"is_poisoned"`
	IsOverridden bool   `json:"is_overridden"`
	Note         string `json:"note,omitempty"`
}

type ConnectResult struct {
	Domain    string `json:"domain"`
	Category  string `json:"category"`
	ResolvedIP string `json:"resolved_ip"`
	UsedDNS   string `json:"used_dns"`
	DNSOk     bool   `json:"dns_ok"`
	TLSOk     bool   `json:"tls_ok"`
	HTTPCode  int    `json:"http_code,omitempty"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

type DPIResult struct {
	Domain      string `json:"domain"`
	RealIP      string `json:"real_ip"`
	RealIPOk    bool   `json:"real_ip_connect_ok"`
	FakeSNIOk   bool   `json:"fake_sni_same_ip_ok"`
	Verdict     string `json:"verdict"` // "dns_only", "dpi_blocked", "not_blocked", "ip_blocked"
	LatencyMs   int64  `json:"latency_ms,omitempty"`
	Error       string `json:"error,omitempty"`
}

type CloudflareResult struct {
	Reachable    bool   `json:"reachable"`
	LatencyMs    int64  `json:"latency_ms"`
	CleanSNIOk   bool   `json:"clean_sni_ok"`
	BlockedSNIOk bool   `json:"blocked_sni_ok"`
	Note         string `json:"note"`
}

type SpeedResult struct {
	TargetHost  string  `json:"target_host"`
	LatencyMs   float64 `json:"latency_ms"`
	JitterMs    float64 `json:"jitter_ms"`
	DownloadKBs float64 `json:"download_kbps,omitempty"`
}

type Report struct {
	Timestamp    string            `json:"timestamp"`
	OS           string            `json:"os"`
	Arch         string            `json:"arch"`
	CustomDNS    string            `json:"custom_dns"`
	ProxyIP      string            `json:"proxy_ip"`
	
	// Section 1: DNS Analysis
	DNSAnalysis  []DNSResult       `json:"dns_analysis"`
	
	// Section 2: Connectivity via custom DNS
	Connectivity []ConnectResult   `json:"connectivity"`
	ConnPass     int               `json:"conn_pass"`
	ConnFail     int               `json:"conn_fail"`
	
	// Section 3: DPI Detection
	DPITests     []DPIResult       `json:"dpi_tests"`
	
	// Section 4: Cloudflare path
	Cloudflare   CloudflareResult  `json:"cloudflare"`
	
	// Section 5: Network quality
	Speed        []SpeedResult     `json:"speed"`
}

// ── DNS helpers ──────────────────────────────────────────────

func resolveWith(domain, dnsAddr string) (string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.Dial("udp", dnsAddr)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := r.LookupHost(ctx, domain)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IPs")
	}
	return ips[0], nil
}

func resolveSystem(domain string) string {
	ips, err := net.LookupHost(domain)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0]
}

// ── TLS / HTTP helpers ──────────────────────────────────────

func probeTLS(domain, ip string) (time.Duration, error) {
	start := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", ip+":443", &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return time.Since(start), err
	}
	conn.Close()
	return time.Since(start), nil
}

func probeHTTP(domain, ip string) (int, time.Duration, error) {
	start := time.Now()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         domain,
			InsecureSkipVerify: true,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "tcp", ip+":443")
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get("https://" + domain + "/")
	elapsed := time.Since(start)
	if err != nil {
		return 0, elapsed, err
	}
	resp.Body.Close()
	return resp.StatusCode, elapsed, nil
}

func tcpPing(host string, port string, count int) (avg, jitter float64) {
	var latencies []float64
	for i := 0; i < count; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", host+":"+port, 5*time.Second)
		if err != nil {
			continue
		}
		latencies = append(latencies, float64(time.Since(start).Microseconds())/1000.0)
		conn.Close()
		time.Sleep(100 * time.Millisecond)
	}
	if len(latencies) == 0 {
		return -1, -1
	}
	var sum float64
	for _, l := range latencies {
		sum += l
	}
	avg = sum / float64(len(latencies))
	if len(latencies) > 1 {
		var diffSum float64
		for i := 1; i < len(latencies); i++ {
			diffSum += math.Abs(latencies[i] - latencies[i-1])
		}
		jitter = diffSum / float64(len(latencies)-1)
	}
	return
}

func downloadSpeed(url string) float64 {
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	start := time.Now()
	resp, err := client.Get(url)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(start).Seconds()
	if elapsed == 0 {
		return -1
	}
	return float64(n) / 1024.0 / elapsed // KB/s
}

// ── Printers ────────────────────────────────────────────────

func header(title string) {
	fmt.Println()
	fmt.Printf("══ %s %s\n", title, strings.Repeat("═", 52-len(title)))
}

func statusIcon(ok bool) string {
	if ok {
		return "✅"
	}
	return "❌"
}

// ── Main ────────────────────────────────────────────────────

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║      SNI Probe — Network Diagnostic Tool            ║")
	fmt.Println("║      github.com/ars1364/sni-probe                   ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")

	report := Report{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		CustomDNS: customDNS,
		ProxyIP:   proxyIP,
	}

	// ── Section 1: DNS Analysis ─────────────────────────────
	header("1. DNS ANALYSIS (poisoning & override detection)")
	fmt.Printf("  Custom DNS: %s | Public DNS: %s\n\n", customDNS, publicDNS)

	dnsTestDomains := []string{
		"discord.com", "twitch.tv", "battle.net",
		"google.com", "github.com", "cloudflare.com",
		"steam.steampowered.com", "chatgpt.com",
	}

	for _, d := range dnsTestDomains {
		dr := DNSResult{Domain: d}
		dr.CustomDNSIP, _ = resolveWith(d, customDNS)
		dr.PublicDNSIP, _ = resolveWith(d, publicDNS)
		dr.SystemDNSIP = resolveSystem(d)

		// Detect poisoning: system DNS returns private/bogus IP while public DNS returns real
		if dr.SystemDNSIP != "" && dr.PublicDNSIP != "" && dr.SystemDNSIP != dr.PublicDNSIP {
			if strings.HasPrefix(dr.SystemDNSIP, "10.") || strings.HasPrefix(dr.SystemDNSIP, "127.") {
				dr.IsPoisoned = true
				dr.Note = "ISP DNS returns bogus IP"
			}
		}
		// Detect override: custom DNS returns proxy/VPS IP
		if dr.CustomDNSIP == proxyIP || dr.CustomDNSIP == vpsIP {
			dr.IsOverridden = true
			dr.Note = fmt.Sprintf("Overridden → %s", dr.CustomDNSIP)
		}
		if dr.CustomDNSIP == "" {
			dr.Note = "Custom DNS unreachable"
		}

		tag := "  "
		if dr.IsPoisoned {
			tag = "☠️"
		} else if dr.IsOverridden {
			tag = "🔀"
		}
		fmt.Printf("  %s %-30s sys=%-16s pub=%-16s cust=%-16s %s\n",
			tag, d, dr.SystemDNSIP, dr.PublicDNSIP, dr.CustomDNSIP, dr.Note)
		report.DNSAnalysis = append(report.DNSAnalysis, dr)
	}
	fmt.Println("\n  Legend: ☠️=ISP poisoned  🔀=DNS overridden to proxy")

	// ── Section 2: Connectivity via custom DNS ──────────────
	header("2. SERVICE CONNECTIVITY (via custom DNS)")

	type job struct {
		domain   string
		category string
	}
	var jobs []job
	for cat, domains := range testDomains {
		for _, d := range domains {
			jobs = append(jobs, job{d, cat})
		}
	}
	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].category == jobs[j].category {
			return jobs[i].domain < jobs[j].domain
		}
		return jobs[i].category < jobs[j].category
	})

	results := make([]ConnectResult, len(jobs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxWorkers)

	fmt.Printf("  Testing %d domains across %d services...\n\n", len(jobs), len(testDomains))

	for i, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, j job) {
			defer wg.Done()
			defer func() { <-sem }()

			r := ConnectResult{Domain: j.domain, Category: j.category, UsedDNS: customDNS}
			ip, err := resolveWith(j.domain, customDNS)
			if err != nil {
				r.Error = "DNS: " + err.Error()
				results[idx] = r
				return
			}
			r.ResolvedIP = ip
			r.DNSOk = true

			code, latency, err := probeHTTP(j.domain, ip)
			r.LatencyMs = latency.Milliseconds()
			r.HTTPCode = code
			if err != nil {
				errStr := err.Error()
				if strings.Contains(errStr, "reset") {
					r.Error = "Connection RESET (DPI?)"
				} else if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
					r.Error = "Timeout"
				} else {
					r.Error = errStr
				}
			} else if code > 0 {
				r.TLSOk = true
			}
			results[idx] = r
		}(i, j)
	}
	wg.Wait()

	curCat := ""
	for _, r := range results {
		if r.Category != curCat {
			curCat = r.Category
			fmt.Printf("\n  [%s]\n", curCat)
		}
		detail := fmt.Sprintf("HTTP %d  %dms  via %s", r.HTTPCode, r.LatencyMs, r.ResolvedIP)
		if !r.TLSOk {
			detail = r.Error
		}
		fmt.Printf("    %s %-40s %s\n", statusIcon(r.TLSOk), r.Domain, detail)
	}

	for _, r := range results {
		if r.TLSOk {
			report.ConnPass++
		} else {
			report.ConnFail++
		}
	}
	report.Connectivity = results

	fmt.Printf("\n  Pass: %d/%d  |  Fail: %d/%d\n", report.ConnPass, len(results), report.ConnFail, len(results))

	// ── Section 3: DPI Detection ────────────────────────────
	header("3. DPI DETECTION (SNI-based blocking analysis)")
	fmt.Println("  Testing if ISP blocks by SNI hostname or just DNS poisoning...")
	fmt.Println()

	dpiDomains := []string{"discord.com", "twitch.tv", "battle.net", "chatgpt.com"}

	for _, domain := range dpiDomains {
		dr := DPIResult{Domain: domain}

		// Get real IP from public DNS
		realIP, err := resolveWith(domain, publicDNS)
		if err != nil {
			dr.Error = "Can't resolve real IP"
			dr.Verdict = "unknown"
			report.DPITests = append(report.DPITests, dr)
			fmt.Printf("  ⚠️  %-20s Can't resolve via %s\n", domain, publicDNS)
			continue
		}
		dr.RealIP = realIP

		// Test 1: Connect to real IP with real SNI
		_, err = probeTLS(domain, realIP)
		dr.RealIPOk = err == nil
		if err != nil && strings.Contains(err.Error(), "reset") {
			// Connection reset = likely DPI
		}

		// Test 2: Connect to same IP with fake SNI (DPI evasion test)
		_, err = probeTLS("test-probe-check.example.com", realIP)
		dr.FakeSNIOk = err == nil || (err != nil && !strings.Contains(err.Error(), "reset") && !strings.Contains(err.Error(), "timeout"))

		// Determine verdict
		if dr.RealIPOk {
			dr.Verdict = "not_blocked"
		} else if dr.FakeSNIOk && !dr.RealIPOk {
			dr.Verdict = "dpi_blocked"
		} else if !dr.FakeSNIOk && !dr.RealIPOk {
			dr.Verdict = "ip_blocked"
		} else {
			dr.Verdict = "dns_only"
		}

		icon := "✅"
		switch dr.Verdict {
		case "dpi_blocked":
			icon = "🛡️"
		case "ip_blocked":
			icon = "🚫"
		case "not_blocked":
			icon = "✅"
		default:
			icon = "❓"
		}

		fmt.Printf("  %s %-20s real_ip=%-16s real_sni=%s  fake_sni=%s  → %s\n",
			icon, domain, realIP,
			statusIcon(dr.RealIPOk), statusIcon(dr.FakeSNIOk),
			strings.ToUpper(dr.Verdict))

		report.DPITests = append(report.DPITests, dr)
	}

	fmt.Println("\n  Legend: ✅=not blocked  🛡️=DPI blocks SNI  🚫=IP blocked  ❓=unknown")
	fmt.Println("  real_sni = connect with actual domain name")
	fmt.Println("  fake_sni = connect to same IP with harmless SNI")

	// ── Section 4: Cloudflare Path Test ─────────────────────
	header("4. CLOUDFLARE PATH TEST")
	fmt.Println("  Testing if Cloudflare IPs are reachable and if DPI inspects them...")
	fmt.Println()

	cf := CloudflareResult{}
	// Test 1: Can we reach Cloudflare at all?
	cfIP := "1.1.1.1"
	latency, err := probeTLS("cloudflare.com", cfIP)
	cf.Reachable = err == nil
	cf.LatencyMs = latency.Milliseconds()

	// Test 2: Reach Cloudflare with a clean SNI
	_, err = probeTLS("clean-test.example.com", "162.159.137.232")
	cf.CleanSNIOk = err == nil || (err != nil && !strings.Contains(err.Error(), "reset"))

	// Test 3: Reach Cloudflare IP with blocked SNI (discord.com)
	_, err = probeTLS("discord.com", "162.159.137.232")
	cf.BlockedSNIOk = err == nil

	if cf.CleanSNIOk && !cf.BlockedSNIOk {
		cf.Note = "Cloudflare reachable but DPI blocks specific SNIs — Iranian reverse proxy needed"
	} else if cf.CleanSNIOk && cf.BlockedSNIOk {
		cf.Note = "Cloudflare fully reachable — no DPI on Cloudflare path"
	} else if !cf.CleanSNIOk {
		cf.Note = "Cloudflare IPs unreachable — severe filtering"
	}

	report.Cloudflare = cf
	fmt.Printf("  Cloudflare reachable:     %s (%dms)\n", statusIcon(cf.Reachable), cf.LatencyMs)
	fmt.Printf("  Clean SNI to CF IP:       %s\n", statusIcon(cf.CleanSNIOk))
	fmt.Printf("  Blocked SNI to CF IP:     %s\n", statusIcon(cf.BlockedSNIOk))
	fmt.Printf("  Assessment: %s\n", cf.Note)

	// ── Section 5: Network Quality ──────────────────────────
	header("5. NETWORK QUALITY")

	speedTargets := []struct {
		name string
		host string
		port string
	}{
		{"Custom DNS", strings.Split(customDNS, ":")[0], "53"},
		{"Cloudflare", "1.1.1.1", "443"},
		{"Google", "google.com", "443"},
		{"Proxy (IR)", proxyIP, "443"},
	}

	for _, t := range speedTargets {
		avg, jitter := tcpPing(t.host, t.port, 5)
		sr := SpeedResult{
			TargetHost: t.name + " (" + t.host + ":" + t.port + ")",
			LatencyMs:  math.Round(avg*100) / 100,
			JitterMs:   math.Round(jitter*100) / 100,
		}

		if avg < 0 {
			fmt.Printf("  ❌ %-35s unreachable\n", t.name)
		} else {
			fmt.Printf("  📡 %-35s latency=%.1fms  jitter=%.1fms\n", t.name, avg, jitter)
		}
		report.Speed = append(report.Speed, sr)
	}

	// Quick download test
	fmt.Println()
	fmt.Print("  ⏬ Download speed test (Cloudflare)... ")
	speed := downloadSpeed("https://speed.cloudflare.com/__down?bytes=1000000")
	if speed > 0 {
		fmt.Printf("%.0f KB/s (%.1f Mbps)\n", speed, speed*8/1024)
	} else {
		fmt.Println("failed")
	}

	// ── Summary ─────────────────────────────────────────────
	header("SUMMARY")

	// Count DPI blocked
	dpiBlocked := 0
	notBlocked := 0
	for _, d := range report.DPITests {
		if d.Verdict == "dpi_blocked" {
			dpiBlocked++
		}
		if d.Verdict == "not_blocked" {
			notBlocked++
		}
	}

	// Count DNS poisoned
	poisoned := 0
	for _, d := range report.DNSAnalysis {
		if d.IsPoisoned {
			poisoned++
		}
	}

	fmt.Printf("  Services via custom DNS:  %d pass / %d fail\n", report.ConnPass, report.ConnFail)
	fmt.Printf("  DNS poisoned domains:     %d detected\n", poisoned)
	fmt.Printf("  DPI blocked domains:      %d (SNI inspection)\n", dpiBlocked)
	fmt.Printf("  Freely accessible:        %d\n", notBlocked)
	fmt.Printf("  Cloudflare path:          %s\n", cf.Note)

	if report.ConnPass > 0 && report.ConnFail == 0 {
		fmt.Println("\n  🎉 All services reachable via custom DNS!")
	} else if report.ConnPass > 0 {
		fmt.Println("\n  ⚠️  Some services blocked. Check DPI results above.")
	} else {
		fmt.Println("\n  ❌ Major connectivity issues. Check DNS and network.")
	}

	// ── Save report ─────────────────────────────────────────
	reportFile := fmt.Sprintf("sni-probe-report-%s.json", time.Now().Format("20060102-150405"))
	f, err := os.Create(reportFile)
	if err == nil {
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		enc.Encode(report)
		f.Close()
		fmt.Printf("\n  📄 Report saved: %s\n", reportFile)
	}

	fmt.Println()
	fmt.Println("  Share the JSON report file for troubleshooting.")
	fmt.Println()
}
