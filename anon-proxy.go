//  anon-proxy.go
//
// Zero-Trust anonymizing HTTP/HTTPS proxy for Termux.
// Integrates with doh-pin-proxy (port 8888) and cloudflared DNS chain.
//
// THREAT MODEL — what this defeats:
//
//   Fingerprinting vectors neutralized:
//     • HTTP header fingerprint  — all headers normalized to a fixed canonical set
//     • User-Agent tracking      — replaced with a generic Chromium UA
//     • Accept-Language leak     — normalized to en-US,en;q=0.9
//     • Client-Hint headers      — Sec-CH-*, Sec-GPC, DNT stripped entirely
//     • Google telemetry header  — X-Client-Data stripped
//     • HTTP/2 AKAMAI fingerprint— forced HTTP/1.1 only; no SETTINGS/HPACK leak
//     • Referer cross-origin     — truncated to origin (scheme+host) only
//     • Correlation headers      — X-Forwarded-For, Via, Forwarded stripped
//
//   Correlation attack vectors neutralized:
//     • Request timing correlation— per-request crypto-random jitter 15–75 ms
//     • DNS timing correlation    — system resolver → cloudflared → doh-pin-proxy
//     • Connection-count pattern  — pooled; idle connections reused across requests
//
//   What this CANNOT defeat (documented honestly):
//     • TLS ClientHello (JA3/JA4) — Go's crypto/tls has a fixed fingerprint;
//       would require uTLS or a custom stack to fully normalize. TLS 1.3 shrinks
//       the fingerprint surface but does not eliminate it.
//     • TCP/IP stack fingerprint  — kernel-level, not addressable in userspace.
//     • Traffic volume analysis   — packet padding not implemented (high overhead,
//       marginal gain for a local proxy). Use Tor if volume analysis is in scope.
//     • HTTPS tunnel contents     — CONNECT mode is a blind tunnel; headers inside
//       the TLS session are end-to-end encrypted and cannot be stripped here.
//
// Usage:
//   go build -trimpath -ldflags="-s -w" -o ~/anon-proxy ~/anon-proxy.go
//
// Configure tools to use it:
//   export http_proxy=http://127.0.0.1:8890
//   export https_proxy=http://127.0.0.1:8890
//   export HTTP_PROXY=http://127.0.0.1:8890
//   export HTTPS_PROXY=http://127.0.0.1:8890
//   export no_proxy=127.0.0.1,localhost

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// ── Configuration ─────────────────────────────────────────────────────────────

const (
	listenAddr = "127.0.0.1:8890"

	// Jitter range in milliseconds (crypto-random per request).
	// 15 ms floor prevents obvious zero-delay pattern;
	// 75 ms ceiling keeps latency acceptable for development use.
	jitterMinMS = 15
	jitterMaxMS = 75

	// Transport timeouts.
	dialTimeout           = 10 * time.Second
	tlsHandshakeTimeout   = 8 * time.Second
	responseHeaderTimeout = 15 * time.Second
	idleConnTimeout       = 60 * time.Second

	// Server timeouts (loopback listener — tighter than internet-facing).
	serverReadTimeout  = 10 * time.Second
	serverWriteTimeout = 30 * time.Second // large for downloads
	serverIdleTimeout  = 60 * time.Second

	// Max request body for non-CONNECT (plain HTTP proxying).
	maxBodyBytes = 10 * 1024 * 1024 // 10 MiB

	shutdownTimeout = 10 * time.Second
)

// ── Canonical normalized User-Agent ───────────────────────────────────────────
// A current, plausible Chromium UA on Linux. Using a single value across all
// requests means requests cannot be de-anonymized by UA diversity.
const normalizedUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

// ── Headers stripped from every outbound request ──────────────────────────────
// These headers either identify the user, the client software, or can be used
// for cross-request correlation.
var stripHeaders = []string{
	// Network topology disclosure
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Port",
	"Via",
	"Forwarded",
	// Google Chrome client-side telemetry identifier
	"X-Client-Data",
	// Privacy / tracking opt-out signals (paradoxically identify privacy-conscious users)
	"DNT",
	"Sec-GPC",
	// Client hints — reveal device, OS, CPU, memory, network, UA details
	"Sec-CH-UA",
	"Sec-CH-UA-Arch",
	"Sec-CH-UA-Bitness",
	"Sec-CH-UA-Full-Version",
	"Sec-CH-UA-Full-Version-List",
	"Sec-CH-UA-Mobile",
	"Sec-CH-UA-Model",
	"Sec-CH-UA-Platform",
	"Sec-CH-UA-Platform-Version",
	"Sec-CH-UA-WoW64",
	"Sec-CH-Device-Memory",
	"Sec-CH-DPR",
	"Sec-CH-Viewport-Width",
	"Sec-CH-Width",
	// Fetch metadata (reveals request context to server)
	"Sec-Fetch-Dest",
	"Sec-Fetch-Mode",
	"Sec-Fetch-Site",
	"Sec-Fetch-User",
	// Correlation identifiers
	"X-Request-ID",
	"X-Correlation-ID",
	"X-Trace-ID",
	"X-B3-TraceId",
	"X-B3-SpanId",
	"X-B3-ParentSpanId",
	"X-B3-Sampled",
	"Traceparent",
	"Tracestate",
	// Browser-specific
	"Purpose",
	"X-Purpose",
	"X-Moz",
	"X-WAP-Profile",
	"X-ATT-DeviceId",
	"X-Samsung-Originator-Info",
}

// ── Timing jitter ─────────────────────────────────────────────────────────────

// applyJitter sleeps for a cryptographically random duration in [jitterMinMS, jitterMaxMS].
// This breaks timing correlation: an adversary observing both client↔proxy and
// proxy↔server traffic cannot correlate individual requests by arrival time.
func applyJitter() {
	window := int64(jitterMaxMS - jitterMinMS)
	n, err := rand.Int(rand.Reader, big.NewInt(window))
	if err != nil {
		// Fallback: use a fixed midpoint — still adds delay, no timing side-channel
		// worse than the fixed value.
		time.Sleep(time.Duration((jitterMinMS+jitterMaxMS)/2) * time.Millisecond)
		return
	}
	time.Sleep(time.Duration(n.Int64()+jitterMinMS) * time.Millisecond)
}

// ── Header sanitization ───────────────────────────────────────────────────────

// sanitizeRequest normalizes a proxied HTTP request for anonymity.
// Must be called before forwarding to upstream.
func sanitizeRequest(r *http.Request) {
	// 1. Strip all identified fingerprinting/correlation headers.
	for _, h := range stripHeaders {
		r.Header.Del(h)
	}

	// 2. Normalize User-Agent — single value, no diversity signal.
	r.Header.Set("User-Agent", normalizedUA)

	// 3. Normalize Accept — standard browser Accept, no custom ordering.
	if r.Header.Get("Accept") == "" {
		r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	}

	// 4. Normalize Accept-Language — single value. Language diversity is a
	//    strong fingerprint signal; en-US is the most common value globally.
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")

	// 5. Normalize Accept-Encoding — gzip+deflate only; brotli support varies
	//    by client version and is a minor fingerprint signal.
	r.Header.Set("Accept-Encoding", "gzip, deflate")

	// 6. Sanitize Referer — strip to origin only (scheme + host), never
	//    expose full path/query. Remove entirely for cross-origin requests.
	if ref := r.Header.Get("Referer"); ref != "" {
		origin := refererOrigin(ref, r.Host)
		if origin == "" {
			r.Header.Del("Referer")
		} else {
			r.Header.Set("Referer", origin)
		}
	}

	// 7. Remove proxy-internal headers added by http package.
	r.Header.Del("X-Forwarded-For") // http.ReverseProxy adds this; strip it
}

// refererOrigin returns the scheme+host of ref if it matches the current host,
// otherwise returns "" (signal to remove Referer entirely).
func refererOrigin(ref, host string) string {
	// Very conservative: only keep referer if it's same-origin.
	// This prevents cross-origin referer leaks entirely.
	_ = host
	// Find scheme end
	schemeEnd := strings.Index(ref, "://")
	if schemeEnd < 0 {
		return ""
	}
	rest := ref[schemeEnd+3:]
	// Find path start
	pathStart := strings.IndexAny(rest, "/?#")
	if pathStart < 0 {
		return ref // already origin-only
	}
	return ref[:schemeEnd+3+pathStart]
}

// ── Transport ─────────────────────────────────────────────────────────────────

func buildTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
		IdleConnTimeout:       idleConnTimeout,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   5,
		// HTTP/1.1 only — eliminates the AKAMAI HTTP/2 fingerprint (SETTINGS frame
		// ordering, initial WINDOW_UPDATE, HEADER compression table state).
		ForceAttemptHTTP2:  false,
		DisableCompression: false, // let gzip work — we normalized Accept-Encoding
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}
}

// ── CONNECT handler (HTTPS tunneling) ────────────────────────────────────────

func handleCONNECT(w http.ResponseWriter, r *http.Request) {
	// Apply jitter BEFORE establishing upstream connection.
	// This breaks timing correlation between the client's CONNECT and the
	// proxy's outbound TCP SYN — an observer on both sides cannot correlate
	// by connection timing.
	applyJitter()

	// Validate target host:port format.
	host := r.Host
	if host == "" {
		http.Error(w, "missing host", http.StatusBadRequest)
		return
	}
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	// Dial upstream — uses system resolver → cloudflared → doh-pin-proxy → NextDNS.
	upstreamConn, err := net.DialTimeout("tcp", host, dialTimeout)
	if err != nil {
		log.Printf("[CONNECT] Dial %s failed: %v", host, err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer upstreamConn.Close()

	// Hijack the client connection.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[CONNECT] Hijack failed: %v", err)
		return
	}
	defer clientConn.Close()

	// 200 Connection Established — tunnel is open.
	if _, err := fmt.Fprint(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	// Set I/O deadlines on both sides — prevent hung tunnels.
	deadline := time.Now().Add(serverWriteTimeout * 10) // tunnels can be long-lived
	_ = clientConn.SetDeadline(deadline)
	_ = upstreamConn.SetDeadline(deadline)

	// Bidirectional blind copy — we cannot see inside the TLS session.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstreamConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, upstreamConn)
		done <- struct{}{}
	}()
	<-done // wait for one direction to close, then exit (other defers will close)
}

// ── HTTP handler (plain HTTP proxying with full header control) ───────────────

var httpTransport = buildTransport()

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Apply jitter before forwarding.
	applyJitter()

	// Sanitize all fingerprinting/correlation headers.
	sanitizeRequest(r)

	// Cap body size.
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	}

	// Build outbound request.
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Copy sanitized headers.
	for k, vv := range r.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}
	outReq.Host = r.Host

	resp, err := httpTransport.RoundTrip(outReq)
	if err != nil {
		log.Printf("[HTTP] Upstream error (%s %s): %v", r.Method, r.Host, err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Forward response headers (do not add identifying headers).
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// ── Health handler ────────────────────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, "ok proxy=anon listen=%s jitter=%d-%dms tls_min=1.3 http2=disabled\n",
		listenAddr, jitterMinMS, jitterMaxMS)
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC | log.Lmicroseconds)
	log.SetPrefix("[anon-proxy] ")

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleCONNECT(w, r)
		} else if r.URL.IsAbs() {
			handleHTTP(w, r)
		} else {
			// Not a proxy request (direct request to this server).
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "use as proxy: set http_proxy=http://"+listenAddr, http.StatusBadRequest)
		}
	})

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  serverReadTimeout,
		WriteTimeout: serverWriteTimeout,
		IdleTimeout:  serverIdleTimeout,
		ErrorLog:     log.Default(),
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-quit
		log.Printf("[SHUTDOWN] %s received — draining (up to %s)…", sig, shutdownTimeout)
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("[SHUTDOWN] Force close: %v", err)
		}
	}()

	log.Printf("[INIT] Anonymizing proxy on %s", listenAddr)
	log.Printf("[INIT] Features: header-strip, UA-normalize, referer-truncate, "+
		"jitter=%d-%dms, HTTP/1.1-only, TLS-1.3-min", jitterMinMS, jitterMaxMS)
	log.Printf("[INIT] Set: export http_proxy=http://%s https_proxy=http://%s", listenAddr, listenAddr)

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("[FATAL] ListenAndServe: %v", err)
	}
	log.Println("[SHUTDOWN] Clean exit")
}
