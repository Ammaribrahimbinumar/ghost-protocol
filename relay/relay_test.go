package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const adminToken = "test-admin-token-0123456789abcdef0123456789"

type env struct {
	t     *testing.T
	clock time.Time
	st    *Store
	srv   *Server
	ts    *httptest.Server
}

func newEnv(t *testing.T, mod func(*Config, *Store)) *env {
	t.Helper()
	e := &env{t: t, clock: time.Unix(1_800_000_000, 0)}
	e.st = NewStore(time.Hour, 1000, "")
	e.st.now = func() time.Time { return e.clock }
	cfg := DefaultConfig(adminToken)
	cfg.IPBurst, cfg.IPRate = 100000, 100000 // effectively unlimited unless a test lowers it
	cfg.MailboxBurst, cfg.MailboxRate = 100000, 100000
	if mod != nil {
		mod(&cfg, e.st)
	}
	e.srv = NewServer(e.st, cfg)
	e.ts = httptest.NewServer(e.srv.Handler())
	t.Cleanup(e.ts.Close)
	return e
}

func (e *env) raw(method, path string, body []byte, hdr map[string]string) *http.Response {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.ts.URL+path, bytes.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}

func (e *env) invite() string {
	e.t.Helper()
	resp := e.raw("POST", "/v1/admin/invites", nil, map[string]string{"Authorization": "Bearer " + adminToken})
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		e.t.Fatalf("invite: %d", resp.StatusCode)
	}
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out["invite"]
}

type client struct {
	e       *env
	name    string
	pub     []byte
	priv    *ecdsa.PrivateKey
	mailbox string
}

func (e *env) registerReq(invite, username string, pub []byte, prekeys [][]byte) *http.Response {
	body, _ := json.Marshal(registerReq{Invite: invite, Username: username, AuthPub: pub, Bundle: []byte("synthetic-public-bundle-" + username), Prekeys: prekeys})
	return e.raw("POST", "/v1/register", body, nil)
}

func (e *env) newUser(name string, prekeys ...[]byte) *client {
	e.t.Helper()
	pub, priv := newAuthKey(e.t)
	resp := e.registerReq(e.invite(), name, pub, prekeys)
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		e.t.Fatalf("register %s: %d", name, resp.StatusCode)
	}
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return &client{e: e, name: name, pub: pub, priv: priv, mailbox: out["mailbox_id"]}
}

// newAuthKey returns a fresh ECDSA P-256 key: the public half as X.509 SPKI DER (what the relay stores).
func newAuthKey(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der, priv
}

func sigHeaders(mailbox string, priv *ecdsa.PrivateKey, method, path string, body []byte, ts int64, nonce string) map[string]string {
	tss := strconv.FormatInt(ts, 10)
	digest := sha256.Sum256(canonical(method, path, tss, nonce, body))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		panic(err)
	}
	return map[string]string{
		"X-Mailbox": mailbox, "X-Timestamp": tss, "X-Nonce": nonce,
		"X-Signature": base64.StdEncoding.EncodeToString(sig),
	}
}

func (c *client) do(method, path string, body []byte) *http.Response {
	return c.e.raw(method, path, body, sigHeaders(c.mailbox, c.priv, method, path, body, c.e.clock.Unix(), randomID(12)))
}

func readJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

func status(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("status = %d, want %d", resp.StatusCode, want)
	}
}

func TestInviteSingleUseAndUsernameCollision(t *testing.T) {
	e := newEnv(t, nil)
	pub, _ := newAuthKey(t)
	inv := e.invite()
	status(t, e.registerReq(inv, "alice", pub, nil), 201)
	status(t, e.registerReq(inv, "alice2", pub, nil), 403) // invite already consumed

	inv2 := e.invite()
	status(t, e.registerReq(inv2, "alice", pub, nil), 409) // username taken
	status(t, e.registerReq(inv2, "bob_1", pub, nil), 201) // invite was NOT burned by the collision

	status(t, e.registerReq("not-a-real-invite", "carol", pub, nil), 403)
	status(t, e.registerReq(e.invite(), "A!", pub, nil), 400)        // bad username
	status(t, e.registerReq(e.invite(), "dave", pub[:10], nil), 400) // bad key length
}

func TestRegisterRejectsWrongKeyTypesAndMalformedKeys(t *testing.T) {
	e := newEnv(t, nil)
	good, _ := newAuthKey(t)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384der, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	edDer, _ := x509.MarshalPKIXPublicKey(edPub)
	cases := map[string][]byte{
		"P-384 key":      p384der,
		"Ed25519 key":    edDer,
		"empty":          nil,
		"garbage":        bytes.Repeat([]byte{0x7f}, 91),
		"truncated":      good[:len(good)-5],
		"trailing data":  append(append([]byte{}, good...), 0),
		"oversized":      bytes.Repeat([]byte{1}, 400),
		"raw point only": good[len(good)-65:],
	}
	i := 0
	for name, k := range cases {
		i++
		status(t, e.registerReq(e.invite(), "user_"+strconv.Itoa(i), k, nil), 400)
		_ = name
	}
	status(t, e.registerReq(e.invite(), "gooduser", good, nil), 201) // control: a valid P-256 key is accepted
}

func TestAdminInviteRequiresToken(t *testing.T) {
	e := newEnv(t, nil)
	status(t, e.raw("POST", "/v1/admin/invites", nil, nil), 401)
	status(t, e.raw("POST", "/v1/admin/invites", nil, map[string]string{"Authorization": "Bearer wrong"}), 401)
}

func TestPrekeysArePoppedOnce(t *testing.T) {
	e := newEnv(t, nil)
	e.newUser("alice", []byte("pk1"), []byte("pk2"))
	for _, want := range []string{"pk1", "pk2", ""} {
		var out struct {
			Prekey []byte `json:"one_time_prekey"`
			Bundle []byte `json:"bundle"`
		}
		readJSON(t, e.raw("GET", "/v1/bundle/alice", nil, nil), &out)
		if string(out.Prekey) != want {
			t.Fatalf("prekey = %q, want %q", out.Prekey, want)
		}
		if len(out.Bundle) == 0 {
			t.Fatal("bundle missing")
		}
	}
	status(t, e.raw("GET", "/v1/bundle/nobody", nil, nil), 404)
}

func TestOpaqueRoundTripAndAck(t *testing.T) {
	e := newEnv(t, nil)
	alice, bob := e.newUser("alice"), e.newUser("bob")

	ct := make([]byte, 2000) // stands in for client-produced ciphertext
	_, _ = rand.Read(ct)
	status(t, alice.do("POST", "/v1/send/"+bob.mailbox, ct), 202)

	var in struct {
		Messages []Delivered `json:"messages"`
	}
	readJSON(t, bob.do("GET", "/v1/inbox", nil), &in)
	if len(in.Messages) != 1 || !bytes.Equal(in.Messages[0].Body, ct) {
		t.Fatal("relay altered or lost the opaque payload")
	}
	// A different user sees nothing.
	var other struct {
		Messages []Delivered `json:"messages"`
	}
	readJSON(t, alice.do("GET", "/v1/inbox", nil), &other)
	if len(other.Messages) != 0 {
		t.Fatal("inbox leaked across mailboxes")
	}
	ack, _ := json.Marshal(map[string][]string{"ids": {in.Messages[0].ID}})
	status(t, bob.do("POST", "/v1/ack", ack), 204)
	readJSON(t, bob.do("GET", "/v1/inbox", nil), &in)
	if len(in.Messages) != 0 {
		t.Fatal("acknowledged envelope still queued")
	}
}

func TestAuthRejections(t *testing.T) {
	e := newEnv(t, nil)
	alice, bob, carol := e.newUser("alice"), e.newUser("bob"), e.newUser("carol")
	_, otherPriv := newAuthKey(t)
	path := "/v1/send/" + bob.mailbox
	body := []byte("payload")
	now := e.clock.Unix()
	ok := func(nonce string) map[string]string {
		return sigHeaders(alice.mailbox, alice.priv, "POST", path, body, now, nonce)
	}

	status(t, e.raw("POST", path, body, ok("nonce-valid-1")), 202)

	// replay of the exact same signed request
	status(t, e.raw("POST", path, body, ok("nonce-valid-1")), 401)

	// signature by the wrong key
	status(t, e.raw("POST", path, body, sigHeaders(alice.mailbox, otherPriv, "POST", path, body, now, "nonce-wrongkey")), 401)

	// unknown mailbox
	status(t, e.raw("POST", path, body, sigHeaders("no-such-mailbox", alice.priv, "POST", path, body, now, "nonce-unknown")), 401)

	// stale and future timestamps
	status(t, e.raw("POST", path, body, sigHeaders(alice.mailbox, alice.priv, "POST", path, body, now-120, "nonce-stale0")), 401)
	status(t, e.raw("POST", path, body, sigHeaders(alice.mailbox, alice.priv, "POST", path, body, now+120, "nonce-future")), 401)

	// body tampered after signing
	status(t, e.raw("POST", path, []byte("tampered"), ok("nonce-tamper-body")), 401)

	// request redirected to a different recipient after signing
	status(t, e.raw("POST", "/v1/send/"+carol.mailbox, body, ok("nonce-redirect")), 401)

	// malformed signature
	h := ok("nonce-badsig-01")
	h["X-Signature"] = "!!!notbase64"
	status(t, e.raw("POST", path, body, h), 401)

	// missing headers entirely
	status(t, e.raw("POST", path, body, nil), 401)

	// Only the single valid message arrived.
	var in struct {
		Messages []Delivered `json:"messages"`
	}
	readJSON(t, bob.do("GET", "/v1/inbox", nil), &in)
	if len(in.Messages) != 1 {
		t.Fatalf("expected exactly 1 delivered message, got %d", len(in.Messages))
	}
}

func TestEnvelopeSizeLimit(t *testing.T) {
	e := newEnv(t, nil)
	alice, bob := e.newUser("alice"), e.newUser("bob")
	status(t, alice.do("POST", "/v1/send/"+bob.mailbox, make([]byte, e.srv.cfg.MaxEnvelope+1)), 400)
	status(t, alice.do("POST", "/v1/send/"+bob.mailbox, nil), 400)
}

func TestTTLExpiryWithFakeClock(t *testing.T) {
	e := newEnv(t, nil)
	alice, bob := e.newUser("alice"), e.newUser("bob")
	status(t, alice.do("POST", "/v1/send/"+bob.mailbox, []byte("m1")), 202)

	e.clock = e.clock.Add(30 * time.Minute)
	var in struct {
		Messages []Delivered `json:"messages"`
	}
	readJSON(t, bob.do("GET", "/v1/inbox", nil), &in)
	if len(in.Messages) != 1 {
		t.Fatal("message expired too early")
	}

	e.clock = e.clock.Add(31 * time.Minute) // past the 1h TTL
	readJSON(t, bob.do("GET", "/v1/inbox", nil), &in)
	if len(in.Messages) != 0 {
		t.Fatal("expired message still deliverable")
	}
	if n := e.srv.Maintain(); n != 1 {
		t.Fatalf("Maintain purged %d, want 1", n)
	}
	e.st.mu.Lock()
	left := len(e.st.queues)
	e.st.mu.Unlock()
	if left != 0 {
		t.Fatal("expired ciphertext not removed from memory")
	}
}

func TestQueueCap(t *testing.T) {
	e := newEnv(t, func(_ *Config, st *Store) { st.maxQueue = 3 })
	alice, bob := e.newUser("alice"), e.newUser("bob")
	for i := 0; i < 3; i++ {
		status(t, alice.do("POST", "/v1/send/"+bob.mailbox, []byte("x")), 202)
	}
	status(t, alice.do("POST", "/v1/send/"+bob.mailbox, []byte("x")), 429)
}

func TestRateLimits(t *testing.T) {
	e := newEnv(t, func(c *Config, _ *Store) {
		c.IPBurst, c.IPRate = 3, 0.001
	})
	for i := 0; i < 3; i++ {
		status(t, e.raw("GET", "/v1/bundle/nobody", nil, nil), 404)
	}
	status(t, e.raw("GET", "/v1/bundle/nobody", nil, nil), 429)
	e.clock = e.clock.Add(2500 * time.Second) // refills ~2 tokens
	status(t, e.raw("GET", "/v1/bundle/nobody", nil, nil), 404)

	e2 := newEnv(t, func(c *Config, _ *Store) { c.MailboxBurst, c.MailboxRate = 2, 0.001 })
	alice, bob := e2.newUser("alice"), e2.newUser("bob")
	status(t, alice.do("POST", "/v1/send/"+bob.mailbox, []byte("1")), 202)
	status(t, alice.do("POST", "/v1/send/"+bob.mailbox, []byte("2")), 202)
	status(t, alice.do("POST", "/v1/send/"+bob.mailbox, []byte("3")), 429)
}

func TestDeleteAccountRemovesEverything(t *testing.T) {
	e := newEnv(t, nil)
	alice, bob := e.newUser("alice"), e.newUser("bob")
	status(t, alice.do("POST", "/v1/send/"+bob.mailbox, []byte("m")), 202)
	status(t, bob.do("DELETE", "/v1/account", nil), 204)
	status(t, e.raw("GET", "/v1/bundle/bob", nil, nil), 404)
	status(t, alice.do("POST", "/v1/send/"+bob.mailbox, []byte("m")), 404)
	status(t, bob.do("GET", "/v1/inbox", nil), 401) // credentials gone
	e.st.mu.Lock()
	defer e.st.mu.Unlock()
	if len(e.st.queues) != 0 {
		t.Fatal("queue survived account deletion")
	}
}

// Regression guard: handlers must never write message bodies, usernames,
// invite codes, mailbox IDs or client IPs to the process log.
func TestNothingSensitiveIsLogged(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	e := newEnv(t, nil)
	invite := e.invite()
	pub, priv := newAuthKey(t)
	status(t, e.registerReq(invite, "loguser", pub, nil), 201)
	status(t, e.registerReq(invite, "loguser2", pub, nil), 403) // error paths too
	other := e.newUser("otheruser")
	marker := "PLAINTEXT-MARKER-7f3a"
	me := &client{e: e, name: "loguser", pub: pub, priv: priv}
	var out struct {
		Mailbox string `json:"mailbox_id"`
	}
	readJSON(t, e.raw("GET", "/v1/bundle/loguser", nil, nil), &out)
	me.mailbox = out.Mailbox
	status(t, me.do("POST", "/v1/send/"+other.mailbox, []byte(marker)), 202)
	e.srv.Maintain()

	logged := buf.String()
	for _, s := range []string{marker, "loguser", "otheruser", invite, me.mailbox, other.mailbox, "127.0.0.1"} {
		if strings.Contains(logged, s) {
			t.Fatalf("process log contains sensitive value %q", s)
		}
	}
}

func TestPersistenceStoresNoCiphertextAndNoRawInvites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "accounts.json")
	now := time.Unix(1_800_000_000, 0)
	st := NewStore(time.Hour, 10, path)
	st.now = func() time.Time { return now }

	spare, err := st.CreateInvite()
	if err != nil {
		t.Fatal(err)
	}
	used, _ := st.CreateInvite()
	pub, _ := newAuthKey(t)
	mb, err := st.Register(used, "alice", pub, []byte("bundle"), nil)
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte("CIPHERTEXT-MARKER-91bc")
	if err := st.Enqueue(mb, marker); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateInvite(); err != nil { // force another snapshot after the enqueue
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, marker) || bytes.Contains(data, []byte(spare)) || bytes.Contains(data, []byte(used)) {
		t.Fatal("snapshot contains queued ciphertext or a raw invite code")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode = %v, want 0600", fi.Mode().Perm())
	}

	st2 := NewStore(time.Hour, 10, path)
	st2.now = st.now
	if err := st2.Load(); err != nil {
		t.Fatal(err)
	}
	if _, ok := st2.AuthKey(mb); !ok {
		t.Fatal("account not restored")
	}
	if len(st2.Inbox(mb)) != 0 {
		t.Fatal("queued ciphertext survived restart; queues must be memory-only")
	}
	pub2, _ := newAuthKey(t)
	if _, err := st2.Register(spare, "bob", pub2, []byte("b"), nil); err != nil {
		t.Fatalf("unused invite not restored: %v", err)
	}
	if _, err := st2.Register(used, "carol", pub2, []byte("b"), nil); err == nil {
		t.Fatal("consumed invite was usable again after restart")
	}
}

func TestTLS13OnlyAndCertificateValidation(t *testing.T) {
	st := NewStore(time.Hour, 10, "")
	srv := NewServer(st, DefaultConfig(adminToken))
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.TLS = newTLSConfig()
	ts.StartTLS()
	defer ts.Close()

	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	client := func(cfg *tls.Config) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	}

	resp, err := client(&tls.Config{RootCAs: pool}).Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("trusted TLS 1.3 connection failed: %v", err)
	}
	resp.Body.Close()
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated version %x, want TLS 1.3", resp.TLS.Version)
	}

	if _, err := client(&tls.Config{RootCAs: pool, MaxVersion: tls.VersionTLS12}).Get(ts.URL + "/healthz"); err == nil {
		t.Fatal("server accepted a TLS 1.2-only client")
	}
	// A client that does not trust the server certificate (what a MITM presenting
	// a different certificate looks like) must refuse to connect.
	if _, err := client(&tls.Config{}).Get(ts.URL + "/healthz"); err == nil {
		t.Fatal("client accepted an untrusted certificate")
	}
}

// Structural check only: the relay source must not import symmetric-cipher or
// key-agreement packages. This is not a proof of confidentiality; the property
// that matters is that the relay is never given any key material.
func TestRelayImportsNoDecryptionPrimitives(t *testing.T) {
	forbidden := []string{`"crypto/aes"`, `"crypto/cipher"`, `"crypto/des"`, `"crypto/rc4"`, `"crypto/ecdh"`, `chacha20poly1305`}
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range forbidden {
			if bytes.Contains(src, []byte(bad)) {
				t.Fatalf("%s imports %s", f, bad)
			}
		}
	}
}

var _ = io.Discard

// ---- admin listener, user list, recorded addresses --------------------------------

func (e *env) adminReq(h http.Handler, method, path, token, remote string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remote
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestAdminEndpointsAreRemovedFromPublicHandlerWhenSeparated(t *testing.T) {
	e := newEnv(t, func(c *Config, _ *Store) { c.PublicAdmin = false })
	status(t, e.raw("POST", "/v1/admin/invites", nil, map[string]string{"Authorization": "Bearer " + adminToken}), 404)
	status(t, e.raw("GET", "/v1/admin/users", nil, map[string]string{"Authorization": "Bearer " + adminToken}), 404)
	rr := e.adminReq(e.srv.AdminHandler(), "POST", "/v1/admin/invites", adminToken, "127.0.0.1:5555", nil)
	if rr.Code != 201 {
		t.Fatalf("admin listener should issue invites: %d", rr.Code)
	}
}

func TestAdminHandlerRequiresTokenAndServesNothingElse(t *testing.T) {
	e := newEnv(t, func(c *Config, _ *Store) { c.PublicAdmin = false })
	h := e.srv.AdminHandler()
	for _, tok := range []string{"", "wrong", adminToken + "x"} {
		if rr := e.adminReq(h, "GET", "/v1/admin/users", tok, "127.0.0.1:1", nil); rr.Code != 401 {
			t.Fatalf("token %q: %d", tok, rr.Code)
		}
	}
	for _, path := range []string{"/v1/register", "/v1/inbox", "/v1/bundle/alice", "/healthz"} {
		if rr := e.adminReq(h, "GET", path, adminToken, "127.0.0.1:1", nil); rr.Code != 404 && rr.Code != 405 {
			t.Fatalf("%s must not be served by the admin listener: %d", path, rr.Code)
		}
	}
}

func TestUserListHidesAddressesUnlessRecordingIsOn(t *testing.T) {
	e := newEnv(t, func(c *Config, _ *Store) { c.PublicAdmin = false })
	apub, _ := newAuthKey(t)
	abody, _ := json.Marshal(registerReq{Invite: e.invite2(), Username: "alice", AuthPub: apub, Bundle: []byte("b")})
	if r := e.raw("POST", "/v1/register", abody, nil); r.StatusCode != 201 {
		t.Fatal(r.StatusCode)
	}
	rr := e.adminReq(e.srv.AdminHandler(), "GET", "/v1/admin/users", adminToken, "127.0.0.1:1", nil)
	var out struct {
		Users []struct {
			Username string `json:"username"`
			IP       string `json:"ip"`
		} `json:"users"`
		RecordIP bool `json:"record_ip"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || len(out.Users) != 1 || out.Users[0].Username != "alice" {
		t.Fatalf("bad list %s %v", rr.Body.String(), err)
	}
	if out.Users[0].IP != "" || out.RecordIP || strings.Contains(rr.Body.String(), "127.0.0.1") {
		t.Fatalf("address must not be exposed or kept when recording is off: %s", rr.Body.String())
	}
}

func TestRecordedAddressComesFromCloudflareHeaderOnlyForLoopbackPeers(t *testing.T) {
	e := newEnv(t, func(c *Config, _ *Store) { c.PublicAdmin = false; c.RecordIP = true; c.TrustProxyHeader = true })
	// Registration over real loopback TCP (this is how cloudflared on the same PC reaches the relay) with the header.
	pub, _ := newAuthKey(t)
	body, _ := json.Marshal(registerReq{Invite: e.invite2(), Username: "bob", AuthPub: pub, Bundle: []byte("b"), Prekeys: nil})
	resp := e.raw("POST", "/v1/register", body, map[string]string{"Cf-Connecting-Ip": "203.0.113.77"})
	if resp.StatusCode != 201 {
		t.Fatalf("register: %d", resp.StatusCode)
	}
	list := func() string {
		return e.adminReq(e.srv.AdminHandler(), "GET", "/v1/admin/users", adminToken, "127.0.0.1:1", nil).Body.String()
	}
	if !strings.Contains(list(), `"ip":"203.0.113.77"`) {
		t.Fatalf("header from a loopback peer should be used: %s", list())
	}
	// A request whose TCP peer is NOT loopback must not be able to choose the recorded address with a header.
	h := e.srv.Handler()
	pub2, _ := newAuthKey(t)
	b2, _ := json.Marshal(registerReq{Invite: e.invite2(), Username: "carol", AuthPub: pub2, Bundle: []byte("b")})
	req := httptest.NewRequest("POST", "/v1/register", bytes.NewReader(b2))
	req.RemoteAddr = "198.51.100.9:4000"
	req.Header.Set("Cf-Connecting-Ip", "10.9.9.9")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 201 {
		t.Fatalf("register carol: %d %s", rr.Code, rr.Body.String())
	}
	l := list()
	if strings.Contains(l, "10.9.9.9") || !strings.Contains(l, "198.51.100.9") {
		t.Fatalf("spoofed header from a non-loopback peer must be ignored: %s", l)
	}
}

func TestAddressesAreNeverWrittenToTheSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/accounts.json"
	e := newEnv(t, func(c *Config, st *Store) { c.PublicAdmin = false; c.RecordIP = true; st.persistPath = path })
	pub, _ := newAuthKey(t)
	body, _ := json.Marshal(registerReq{Invite: e.invite2(), Username: "dave", AuthPub: pub, Bundle: []byte("b")})
	if r := e.raw("POST", "/v1/register", body, nil); r.StatusCode != 201 {
		t.Fatal(r.StatusCode)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "dave") {
		t.Fatalf("snapshot missing: %v", err)
	}
	if strings.Contains(string(data), "127.0.0.1") || strings.Contains(string(data), "last_seen") {
		t.Fatalf("snapshot must not contain addresses: %s", data)
	}
}

// invite2 issues an invite through the store directly (the public handler may not expose admin routes).
func (e *env) invite2() string {
	code, err := e.st.CreateInvite()
	if err != nil {
		e.t.Fatal(err)
	}
	return code
}

// ---- snapshot export/import (the admin app keeps the snapshot encrypted itself) ----------------

func TestSnapshotExportImportRoundTripAndGuards(t *testing.T) {
	e := newEnv(t, func(c *Config, _ *Store) { c.PublicAdmin = false })
	h := e.srv.AdminHandler()
	inv := e.adminReq(h, "POST", "/v1/admin/invites", adminToken, "127.0.0.1:1", nil)
	if inv.Code != 201 {
		t.Fatalf("invite: %d", inv.Code)
	}
	exp := e.adminReq(h, "GET", "/v1/admin/export", adminToken, "127.0.0.1:1", nil)
	if exp.Code != 200 || !strings.Contains(exp.Body.String(), `"invites"`) {
		t.Fatalf("export: %d %s", exp.Code, exp.Body.String())
	}
	if strings.Contains(exp.Body.String(), "127.0.0.1") {
		t.Fatal("snapshot must never contain network addresses")
	}
	// token required, and neither endpoint exists on the public handler
	if rr := e.adminReq(h, "GET", "/v1/admin/export", "wrong", "127.0.0.1:1", nil); rr.Code != 401 {
		t.Fatalf("export without token: %d", rr.Code)
	}
	status(t, e.raw("GET", "/v1/admin/export", nil, map[string]string{"Authorization": "Bearer " + adminToken}), 404)
	status(t, e.raw("POST", "/v1/admin/import", nil, map[string]string{"Authorization": "Bearer " + adminToken}), 404)
	// a fresh relay accepts the snapshot; a non-empty one refuses it; garbage is rejected
	e2 := newEnv(t, func(c *Config, _ *Store) { c.PublicAdmin = false })
	h2 := e2.srv.AdminHandler()
	post := func(h http.Handler, body string) int {
		req := httptest.NewRequest("POST", "/v1/admin/import", strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:2"
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	if c := post(h2, "not json"); c != 400 {
		t.Fatalf("garbage: %d", c)
	}
	if c := post(h2, exp.Body.String()); c != 204 {
		t.Fatalf("import: %d", c)
	}
	if e2.st.UnusedInvites() != 1 {
		t.Fatal("invite hash not restored")
	}
	if c := post(h2, exp.Body.String()); c != 409 {
		t.Fatalf("second import must be refused: %d", c)
	}
}
