package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "listen address")
	certFile := flag.String("tls-cert", "", "TLS certificate (PEM)")
	keyFile := flag.String("tls-key", "", "TLS private key (PEM)")
	data := flag.String("data", "", "path for the accounts snapshot (public keys + invite hashes only)")
	ttlHours := flag.Int("ttl-hours", 24*7, "how long undelivered ciphertext is kept")
	ipRate := flag.Float64("ip-rate", 0.5, "sustained requests/second allowed per client address on unauthenticated and auth endpoints")
	ipBurst := flag.Float64("ip-burst", 30, "burst allowance per client address")
	adminAddr := flag.String("admin-addr", "", "serve the admin endpoints ONLY on this loopback address (e.g. 127.0.0.1:8444) and remove them from the public listener")
	recordIP := flag.Bool("record-ip", false, "remember each account's last client address in memory for the admin user list (never written to disk or logs)")
	trustCF := flag.Bool("trust-cf-header", false, "trust Cf-Connecting-Ip when the request arrives from loopback (cloudflared on this machine)")
	insecureDev := flag.Bool("insecure-dev", false, "serve plain HTTP on a loopback address (development only)")
	flag.Parse()

	// The admin token comes from the environment, never from source code or flags.
	token := os.Getenv("GHOST_ADMIN_TOKEN")
	if len(token) < 32 {
		log.Fatal("GHOST_ADMIN_TOKEN must be set to at least 32 characters")
	}

	st := NewStore(time.Duration(*ttlHours)*time.Hour, 1000, *data)
	if err := st.Load(); err != nil {
		log.Fatalf("loading snapshot: %v", err)
	}
	cfg := DefaultConfig(token)
	cfg.IPRate, cfg.IPBurst = *ipRate, *ipBurst
	cfg.RecordIP, cfg.TrustProxyHeader = *recordIP, *trustCF
	if *adminAddr != "" {
		host, _, err := net.SplitHostPort(*adminAddr)
		if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
			log.Fatal("-admin-addr must be a loopback IP address such as 127.0.0.1:8444")
		}
		cfg.PublicAdmin = false
	}
	srv := NewServer(st, cfg)
	if *adminAddr != "" {
		as := &http.Server{Addr: *adminAddr, Handler: srv.AdminHandler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
		go func() { log.Fatal(as.ListenAndServe()) }()
		log.Printf("admin endpoints on %s (loopback only; not served on the public listener)", *adminAddr)
	}

	go func() {
		for range time.Tick(time.Minute) {
			if n := srv.Maintain(); n > 0 {
				log.Printf("expired %d envelopes", n) // count only, no identifiers
			}
		}
	}()

	hs := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		TLSConfig:         newTLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	// No per-request access log is written: request paths contain usernames and
	// mailbox IDs, and connection logs would retain IP addresses.
	if *insecureDev {
		log.Printf("DEV MODE: plain HTTP on %s (do not expose)", *addr)
		log.Fatal(hs.ListenAndServe())
	}
	if *certFile == "" || *keyFile == "" {
		log.Fatal("-tls-cert and -tls-key are required (or use -insecure-dev on loopback)")
	}
	log.Printf("listening with TLS 1.3 on %s", *addr)
	log.Fatal(hs.ListenAndServeTLS(*certFile, *keyFile))
}
