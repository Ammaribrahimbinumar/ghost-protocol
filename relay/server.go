package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"
)

const (
	maxRegisterBody = 512 << 10
	maxBundle       = 8 << 10
	maxAuthPub      = 200
	maxPrekey       = 4 << 10
	maxPrekeyBatch  = 100
	maxPrekeysTotal = 200
	maxAuthedBody   = 128 << 10
	maxClockSkew    = 60 * time.Second
)

var usernameRE = regexp.MustCompile(`^[a-z0-9_]{3,32}$`)

type Config struct {
	AdminToken   string
	MaxEnvelope  int
	IPRate       float64 // tokens/sec for unauthenticated endpoints
	IPBurst      float64
	MailboxRate  float64 // tokens/sec per authenticated mailbox
	MailboxBurst float64
}

func DefaultConfig(adminToken string) Config {
	return Config{AdminToken: adminToken, MaxEnvelope: 64 << 10, IPRate: 0.5, IPBurst: 30, MailboxRate: 2, MailboxBurst: 60}
}

// ---- rate limiting ---------------------------------------------------------

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu   sync.Mutex
	now  func() time.Time
	rate float64
	cap  float64
	m    map[string]*bucket
}

func newLimiter(rate, burst float64, now func() time.Time) *limiter {
	return &limiter{now: now, rate: rate, cap: burst, m: map[string]*bucket{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	b, ok := l.m[key]
	if !ok {
		b = &bucket{tokens: l.cap, last: t}
		l.m[key] = b
	}
	b.tokens += t.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.cap {
		b.tokens = l.cap
	}
	b.last = t
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *limiter) prune(idle time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	for k, b := range l.m {
		if t.Sub(b.last) > idle {
			delete(l.m, k)
		}
	}
}

// ---- server ----------------------------------------------------------------

type Server struct {
	st        *Store
	cfg       Config
	ipRL      *limiter
	mbRL      *limiter
	adminHash [32]byte

	nonceMu sync.Mutex
	nonces  map[string]time.Time

	saltMu   sync.Mutex
	salt     []byte
	saltTime time.Time
}

func NewServer(st *Store, cfg Config) *Server {
	s := &Server{
		st:        st,
		cfg:       cfg,
		ipRL:      newLimiter(cfg.IPRate, cfg.IPBurst, st.now),
		mbRL:      newLimiter(cfg.MailboxRate, cfg.MailboxBurst, st.now),
		adminHash: sha256.Sum256([]byte(cfg.AdminToken)),
		nonces:    map[string]time.Time{},
	}
	s.rotateSalt()
	return s
}

func (s *Server) rotateSalt() {
	s.saltMu.Lock()
	defer s.saltMu.Unlock()
	s.salt = make([]byte, 32)
	if _, err := rand.Read(s.salt); err != nil {
		panic(err)
	}
	s.saltTime = s.st.now()
}

// ipKey derives an ephemeral rate-limit key. The IP is never stored or logged;
// only an HMAC under a salt that is rotated and kept in memory.
func (s *Server) ipKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	s.saltMu.Lock()
	defer s.saltMu.Unlock()
	m := hmac.New(sha256.New, s.salt)
	m.Write([]byte(host))
	return hex.EncodeToString(m.Sum(nil))
}

// Maintain runs expiry and housekeeping; call periodically.
func (s *Server) Maintain() int {
	n := s.st.Purge()
	now := s.st.now()
	s.nonceMu.Lock()
	for k, exp := range s.nonces {
		if now.After(exp) {
			delete(s.nonces, k)
		}
	}
	s.nonceMu.Unlock()
	s.ipRL.prune(10 * time.Minute)
	s.mbRL.prune(10 * time.Minute)
	s.saltMu.Lock()
	rotate := now.Sub(s.saltTime) > 24*time.Hour
	s.saltMu.Unlock()
	if rotate {
		s.rotateSalt()
	}
	return n
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("POST /v1/admin/invites", s.adminInvite)
	mux.HandleFunc("POST /v1/register", s.register)
	mux.HandleFunc("GET /v1/bundle/{username}", s.getBundle)
	mux.HandleFunc("PUT /v1/prekeys", s.auth(s.putPrekeys))
	mux.HandleFunc("POST /v1/send/{mailbox}", s.auth(s.send))
	mux.HandleFunc("GET /v1/inbox", s.auth(s.inbox))
	mux.HandleFunc("POST /v1/ack", s.auth(s.ack))
	mux.HandleFunc("DELETE /v1/account", s.auth(s.deleteAccount))
	return noStore(mux)
}

func noStore(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// ---- unauthenticated endpoints --------------------------------------------

func (s *Server) adminInvite(w http.ResponseWriter, r *http.Request) {
	if !s.ipRL.allow(s.ipKey(r)) {
		fail(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	got := sha256.Sum256([]byte(bearer(r)))
	if s.cfg.AdminToken == "" || !constEq(got[:], s.adminHash[:]) {
		fail(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	code, err := s.st.CreateInvite()
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"invite": code})
}

func bearer(r *http.Request) string {
	const p = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(p) && h[:len(p)] == p {
		return h[len(p):]
	}
	return ""
}

type registerReq struct {
	Invite   string   `json:"invite"`
	Username string   `json:"username"`
	AuthPub  []byte   `json:"auth_pub"`
	Bundle   []byte   `json:"bundle"`
	Prekeys  [][]byte `json:"one_time_prekeys"`
}

// parseAuthKey accepts only an ECDSA P-256 public key in X.509 SubjectPublicKeyInfo DER form, which
// is what Android Keystore and the JDK produce from PublicKey.getEncoded(). Any other key type,
// curve, trailing data or garbage is refused.
func parseAuthKey(der []byte) (*ecdsa.PublicKey, bool) {
	if len(der) == 0 || len(der) > maxAuthPub {
		return nil, false
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, false
	}
	pk, ok := k.(*ecdsa.PublicKey)
	if !ok || pk.Curve != elliptic.P256() {
		return nil, false
	}
	return pk, true
}

func validAuthKey(der []byte) bool {
	_, ok := parseAuthKey(der)
	return ok
}

func validPrekeys(p [][]byte) bool {
	if len(p) > maxPrekeyBatch {
		return false
	}
	for _, k := range p {
		if len(k) == 0 || len(k) > maxPrekey {
			return false
		}
	}
	return true
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if !s.ipRL.allow(s.ipKey(r)) {
		fail(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	var req registerReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRegisterBody)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	if !usernameRE.MatchString(req.Username) || !validAuthKey(req.AuthPub) ||
		len(req.Bundle) == 0 || len(req.Bundle) > maxBundle || !validPrekeys(req.Prekeys) || req.Invite == "" {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	mailbox, err := s.st.Register(req.Invite, req.Username, req.AuthPub, req.Bundle, req.Prekeys)
	switch {
	case errors.Is(err, ErrInvalidInvite):
		fail(w, http.StatusForbidden, "invalid invite")
	case errors.Is(err, ErrUsernameTaken):
		fail(w, http.StatusConflict, "username unavailable")
	case err != nil:
		fail(w, http.StatusInternalServerError, "internal error")
	default:
		writeJSON(w, http.StatusCreated, map[string]string{"mailbox_id": mailbox})
	}
}

func (s *Server) getBundle(w http.ResponseWriter, r *http.Request) {
	if !s.ipRL.allow(s.ipKey(r)) {
		fail(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	mailbox, bundle, prekey, err := s.st.Bundle(r.PathValue("username"))
	if errors.Is(err, ErrNotFound) {
		fail(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	resp := map[string]any{"mailbox_id": mailbox, "bundle": bundle}
	if prekey != nil {
		resp["one_time_prekey"] = prekey
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- authenticated endpoints ----------------------------------------------

type authedHandler func(w http.ResponseWriter, r *http.Request, mailbox string, body []byte)

// canonical builds the string a client must sign:
// METHOD \n PATH \n TIMESTAMP \n NONCE \n hex(SHA-256(body))
func canonical(method, path, ts, nonce string, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte(fmt.Sprintf("%s\n%s\n%s\n%s\n%s", method, path, ts, nonce, hex.EncodeToString(h[:])))
}

func (s *Server) auth(h authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		deny := func() { fail(w, http.StatusUnauthorized, "unauthorized") }
		if !s.ipRL.allow(s.ipKey(r)) {
			fail(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		mailbox := r.Header.Get("X-Mailbox")
		ts := r.Header.Get("X-Timestamp")
		nonce := r.Header.Get("X-Nonce")
		sigB64 := r.Header.Get("X-Signature")
		pub, ok := s.st.AuthKey(mailbox)
		if !ok || len(nonce) < 8 || len(nonce) > 64 {
			deny()
			return
		}
		sec, err := strconv.ParseInt(ts, 10, 64)
		if err != nil {
			deny()
			return
		}
		now := s.st.now()
		skew := now.Sub(time.Unix(sec, 0))
		if skew < -maxClockSkew || skew > maxClockSkew {
			deny()
			return
		}
		sig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil || len(sig) < 8 || len(sig) > 80 {
			deny()
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAuthedBody))
		if err != nil {
			fail(w, http.StatusRequestEntityTooLarge, "too large")
			return
		}
		pk, okKey := parseAuthKey(pub)
		if !okKey {
			deny()
			return
		}
		digest := sha256.Sum256(canonical(r.Method, r.URL.Path, ts, nonce, body))
		if !ecdsa.VerifyASN1(pk, digest[:], sig) {
			deny()
			return
		}
		// Replay protection: only after the signature is proven valid.
		key := mailbox + "|" + nonce
		s.nonceMu.Lock()
		if _, seen := s.nonces[key]; seen {
			s.nonceMu.Unlock()
			deny()
			return
		}
		s.nonces[key] = now.Add(2 * maxClockSkew)
		s.nonceMu.Unlock()
		if !s.mbRL.allow(mailbox) {
			fail(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		h(w, r, mailbox, body)
	}
}

func (s *Server) putPrekeys(w http.ResponseWriter, r *http.Request, mailbox string, body []byte) {
	var req struct {
		Prekeys [][]byte `json:"one_time_prekeys"`
	}
	if json.Unmarshal(body, &req) != nil || len(req.Prekeys) == 0 || !validPrekeys(req.Prekeys) {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := s.st.AddPrekeys(mailbox, req.Prekeys, maxPrekeysTotal); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// send stores the request body, byte for byte, as an opaque envelope.
func (s *Server) send(w http.ResponseWriter, r *http.Request, sender string, body []byte) {
	if len(body) == 0 || len(body) > s.cfg.MaxEnvelope {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	switch err := s.st.Enqueue(r.PathValue("mailbox"), body); {
	case errors.Is(err, ErrNotFound):
		fail(w, http.StatusNotFound, "not found")
	case errors.Is(err, ErrQueueFull):
		fail(w, http.StatusTooManyRequests, "recipient queue full")
	case err != nil:
		fail(w, http.StatusInternalServerError, "internal error")
	default:
		w.WriteHeader(http.StatusAccepted)
	}
}

func (s *Server) inbox(w http.ResponseWriter, r *http.Request, mailbox string, _ []byte) {
	writeJSON(w, http.StatusOK, map[string]any{"messages": s.st.Inbox(mailbox)})
}

func (s *Server) ack(w http.ResponseWriter, r *http.Request, mailbox string, body []byte) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if json.Unmarshal(body, &req) != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	s.st.Ack(mailbox, req.IDs)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request, mailbox string, _ []byte) {
	if err := s.st.DeleteAccount(mailbox); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// newTLSConfig enforces TLS 1.3 as the minimum version.
func newTLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13}
}
