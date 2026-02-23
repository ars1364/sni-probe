package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	listenAddr = "127.0.0.1:53"
	dohURL     = "https://dns.cloudinative.com/dns-query"
	timeout    = 5 * time.Second
)

func main() {
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║      CloudiNative DNS — Encrypted DNS Client    ║")
	fmt.Println("║      Set your DNS to: 127.0.0.1                 ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  DoH Server:  %s\n", dohURL)
	fmt.Printf("  Listening:   %s\n", listenAddr)
	fmt.Println()

	// Start UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		log.Fatalf("❌ Failed to resolve address: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		if strings.Contains(err.Error(), "bind") || strings.Contains(err.Error(), "permission") {
			fmt.Println("❌ Cannot bind to port 53.")
			fmt.Println("   → Run as Administrator (right-click → Run as administrator)")
			fmt.Println("   → Or stop any other DNS service using port 53")
			fmt.Println()
			fmt.Println("Press Enter to exit...")
			fmt.Scanln()
			os.Exit(1)
		}
		log.Fatalf("❌ Failed to listen: %v", err)
	}
	defer udpConn.Close()

	// Also start TCP listener (some apps use TCP DNS)
	tcpLn, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Printf("⚠️  TCP DNS not available: %v", err)
	} else {
		defer tcpLn.Close()
		go serveTCP(tcpLn)
		fmt.Println("  ✅ TCP DNS ready")
	}

	fmt.Println("  ✅ UDP DNS ready")
	fmt.Println()
	fmt.Println("  Now set your DNS to 127.0.0.1 and enjoy!")
	fmt.Println("  Press Ctrl+C to stop.")
	fmt.Println()

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n  Shutting down...")
		udpConn.Close()
		if tcpLn != nil {
			tcpLn.Close()
		}
		os.Exit(0)
	}()

	// HTTP client with custom TLS (skip verify for self-signed certs)
	httpClient := &http.Client{
		Timeout: timeout,
	}

	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if strings.Contains(err.Error(), "closed") {
				return
			}
			log.Printf("read error: %v", err)
			continue
		}

		go handleUDPQuery(udpConn, remoteAddr, buf[:n], httpClient)
	}
}

func handleUDPQuery(conn *net.UDPConn, addr *net.UDPAddr, query []byte, client *http.Client) {
	resp, err := doHTTPQuery(query, client)
	if err != nil {
		log.Printf("  ✗ DoH error: %v", err)
		// Return SERVFAIL
		if len(query) >= 12 {
			servfail := make([]byte, len(query))
			copy(servfail, query)
			servfail[2] = 0x81 // QR=1, RD=1
			servfail[3] = 0x82 // RA=1, RCODE=2 (SERVFAIL)
			conn.WriteToUDP(servfail, addr)
		}
		return
	}

	// Extract domain name for logging
	domain := extractDomainFromQuery(query)
	ip := extractIPFromResponse(resp)
	if domain != "" {
		log.Printf("  ✓ %s → %s", domain, ip)
	}

	conn.WriteToUDP(resp, addr)
}

func serveTCP(ln net.Listener) {
	client := &http.Client{Timeout: timeout}
	for {
		conn, err := ln.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "closed") {
				return
			}
			continue
		}
		go handleTCPConn(conn, client)
	}
}

func handleTCPConn(conn net.Conn, client *http.Client) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// TCP DNS: first 2 bytes = message length
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return
	}
	msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if msgLen > 4096 || msgLen < 12 {
		return
	}

	query := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, query); err != nil {
		return
	}

	resp, err := doHTTPQuery(query, client)
	if err != nil {
		return
	}

	// Write length prefix + response
	respLen := []byte{byte(len(resp) >> 8), byte(len(resp))}
	conn.Write(respLen)
	conn.Write(resp)
}

func doHTTPQuery(query []byte, client *http.Client) ([]byte, error) {
	// RFC 8484: GET with dns parameter (base64url)
	b64 := base64.RawURLEncoding.EncodeToString(query)
	url := fmt.Sprintf("%s?dns=%s", dohURL, b64)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DoH returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// Extract domain name from DNS query for logging
func extractDomainFromQuery(data []byte) string {
	if len(data) < 13 {
		return ""
	}
	pos := 12 // skip header
	var parts []string
	for pos < len(data) {
		labelLen := int(data[pos])
		if labelLen == 0 {
			break
		}
		pos++
		if pos+labelLen > len(data) {
			break
		}
		parts = append(parts, string(data[pos:pos+labelLen]))
		pos += labelLen
	}
	return strings.Join(parts, ".")
}

// Extract first A record IP from DNS response for logging
func extractIPFromResponse(data []byte) string {
	if len(data) < 12 {
		return "?"
	}
	ancount := int(data[6])<<8 | int(data[7])
	if ancount == 0 {
		return "NXDOMAIN"
	}

	// Skip header + question section
	pos := 12
	for pos < len(data) && data[pos] != 0 {
		pos += int(data[pos]) + 1
	}
	pos += 5 // null + qtype(2) + qclass(2)

	// Parse first answer
	for i := 0; i < ancount && pos < len(data); i++ {
		// Skip name (handle compression)
		if pos >= len(data) {
			break
		}
		if data[pos]&0xC0 == 0xC0 {
			pos += 2
		} else {
			for pos < len(data) && data[pos] != 0 {
				pos += int(data[pos]) + 1
			}
			pos++
		}
		if pos+10 > len(data) {
			break
		}
		rtype := int(data[pos])<<8 | int(data[pos+1])
		rdlen := int(data[pos+8])<<8 | int(data[pos+9])
		pos += 10
		if rtype == 1 && rdlen == 4 && pos+4 <= len(data) {
			return fmt.Sprintf("%d.%d.%d.%d", data[pos], data[pos+1], data[pos+2], data[pos+3])
		}
		pos += rdlen
	}
	return "?"
}
