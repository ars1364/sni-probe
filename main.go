package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	dnsServer  = "46.245.69.222:53"
	vpsIP      = "188.40.147.153"
	timeout    = 8 * time.Second
	maxWorkers = 20
)

type ProbeResult struct {
	Domain    string `json:"domain"`
	Category  string `json:"category"`
	ResolvedIP string `json:"resolved_ip"`
	DNSOk     bool   `json:"dns_ok"`
	TLSOk     bool   `json:"tls_ok"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

type Report struct {
	Timestamp  string        `json:"timestamp"`
	DNSServer  string        `json:"dns_server"`
	ProxyIP    string        `json:"proxy_ip"`
	Total      int           `json:"total"`
	DNSPass    int           `json:"dns_pass"`
	TLSPass    int           `json:"tls_pass"`
	TLSFail    int           `json:"tls_fail"`
	Results    []ProbeResult `json:"results"`
}

var testDomains = map[string][]string{
	"Discord": {
		"discord.com",
		"cdn.discordapp.com",
		"gateway.discord.gg",
	},
	"Spotify": {
		"open.spotify.com",
		"accounts.spotify.com",
		"api.spotify.com",
	},
	"Steam/Epic": {
		"epicgames.com",
		"cdn2.unrealengine.com",
	},
	"Riot (LoL/Valorant)": {
		"auth.riotgames.com",
		"riot-client.dyn.riotcdn.net",
	},
	"EA": {
		"accounts.ea.com",
		"signin.ea.com",
		"gateway.ea.com",
	},
	"Xbox Live": {
		"accounts.xboxlive.com",
		"xsts.auth.xboxlive.com",
		"social.xboxlive.com",
	},
	"Nintendo": {
		"accounts.nintendo.com",
		"dragons.p01.lp1.dragons.nintendo.net",
	},
	"Battle.net": {
		"eu.actual.battle.net",
		"us.actual.battle.net",
	},
	"Ubisoft": {
		"connect.ubisoft.com",
		"store.ubisoft.com",
		"public-ubiservices.ubi.com",
	},
	"ChatGPT": {
		"chatgpt.com",
		"auth.openai.com",
	},
	"Claude AI": {
		"claude.ai",
		"www.anthropic.com",
	},
	"Twitch": {
		"www.twitch.tv",
	},
	"Nvidia": {
		"www.nvidia.com",
		"login.nvidia.com",
	},
	"Fortnite": {
		"fortnite-storage-live.s3.amazonaws.com",
	},
	"Google AI": {
		"gemini.google.com",
		"aistudio.google.com",
	},
	"Apple Music": {
		"music.apple.com",
	},
}

func resolveDNS(domain string) (string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx interface{ Deadline() (time.Time, bool) }, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.Dial("udp", dnsServer)
		},
	}
	ips, err := r.LookupHost(nil, domain)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IPs returned")
	}
	return ips[0], nil
}

func probeTLS(domain, ip string) (time.Duration, error) {
	start := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", ip+":443", &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: false,
	})
	if err != nil {
		return time.Since(start), err
	}
	conn.Close()
	return time.Since(start), nil
}

func probe(domain, category string) ProbeResult {
	r := ProbeResult{Domain: domain, Category: category}

	ip, err := resolveDNS(domain)
	if err != nil {
		r.Error = "DNS: " + err.Error()
		return r
	}
	r.ResolvedIP = ip
	r.DNSOk = true

	if ip != vpsIP {
		r.Error = fmt.Sprintf("DNS resolved to %s (expected %s) — zone override missing?", ip, vpsIP)
		return r
	}

	latency, err := probeTLS(domain, ip)
	r.LatencyMs = latency.Milliseconds()
	if err != nil {
		r.Error = "TLS: " + err.Error()
		return r
	}
	r.TLSOk = true
	return r
}

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║         SNI Proxy Connectivity Probe                ║")
	fmt.Println("║         DNS: 46.245.69.222                         ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Println()

	// Flatten domains
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

	results := make([]ProbeResult, len(jobs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxWorkers)

	fmt.Printf("Testing %d domains across %d services...\n\n", len(jobs), len(testDomains))

	for i, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, j job) {
			defer wg.Done()
			defer func() { <-sem }()
			r := probe(j.domain, j.category)
			results[idx] = r

			status := "✅"
			detail := fmt.Sprintf("%dms", r.LatencyMs)
			if !r.TLSOk {
				status = "❌"
				detail = r.Error
			}
			fmt.Printf("  %s %-45s [%s] %s\n", status, r.Domain, r.Category, detail)
		}(i, j)
	}
	wg.Wait()

	// Summary
	report := Report{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		DNSServer: dnsServer,
		ProxyIP:   vpsIP,
		Total:     len(results),
		Results:   results,
	}
	for _, r := range results {
		if r.DNSOk {
			report.DNSPass++
		}
		if r.TLSOk {
			report.TLSPass++
		} else {
			report.TLSFail++
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("─", 56))
	fmt.Printf("  DNS OK: %d/%d  |  TLS OK: %d/%d  |  Failed: %d\n",
		report.DNSPass, report.Total, report.TLSPass, report.Total, report.TLSFail)
	fmt.Println(strings.Repeat("─", 56))

	if report.TLSFail > 0 {
		fmt.Println("\n  Failed domains:")
		for _, r := range results {
			if !r.TLSOk {
				fmt.Printf("    ❌ %s — %s\n", r.Domain, r.Error)
			}
		}
	}

	// Write JSON report
	reportFile := fmt.Sprintf("sni-probe-report-%s.json", time.Now().Format("20060102-150405"))
	f, err := os.Create(reportFile)
	if err == nil {
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		enc.Encode(report)
		f.Close()
		fmt.Printf("\n  📄 Full report saved: %s\n", reportFile)
	}

	fmt.Println()
	fmt.Println("Share the JSON report file for troubleshooting.")
}
