package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Errors returned by Store. Handlers map these to generic HTTP responses.
var (
	ErrInvalidInvite = errors.New("invalid invite")
	ErrUsernameTaken = errors.New("username taken")
	ErrNotFound      = errors.New("not found")
	ErrQueueFull     = errors.New("queue full")
)

// Account holds only PUBLIC material. The relay never receives private keys.
// Bundle and OneTimePrekeys are opaque blobs produced by the client's
// cryptographic library; the relay does not parse them.
type Account struct {
	Username       string   `json:"username"`
	MailboxID      string   `json:"mailbox_id"`
	AuthPub        []byte   `json:"auth_pub"` // ECDSA P-256 (X.509 SPKI DER), relay authentication only
	Bundle         []byte   `json:"bundle"`
	OneTimePrekeys [][]byte `json:"one_time_prekeys"`
}

type envelope struct {
	id      string
	body    []byte // opaque ciphertext, stored byte-for-byte
	expires time.Time
}

type snapshot struct {
	Accounts []*Account `json:"accounts"`
	Invites  []string   `json:"invites"` // SHA-256 hex of unused invite codes (never the codes)
}

// Store keeps accounts, invite hashes and short-lived mailbox queues.
// Queues are memory-only by design: a restart drops undelivered ciphertext
// rather than writing it to disk. Accounts/invites are snapshotted to disk
// (public keys and hashes only) so a restart does not lock users out.
type Store struct {
	mu          sync.Mutex
	now         func() time.Time
	byMailbox   map[string]*Account
	byUsername  map[string]string
	invites     map[string]struct{}
	queues      map[string][]envelope
	ttl         time.Duration
	maxQueue    int
	persistPath string
}

func NewStore(ttl time.Duration, maxQueue int, persistPath string) *Store {
	return &Store{
		now:         time.Now,
		byMailbox:   map[string]*Account{},
		byUsername:  map[string]string{},
		invites:     map[string]struct{}{},
		queues:      map[string][]envelope{},
		ttl:         ttl,
		maxQueue:    maxQueue,
		persistPath: persistPath,
	}
}

func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failure: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashInvite(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// CreateInvite returns a single-use code. Only its hash is retained.
func (s *Store) CreateInvite() (string, error) {
	code := randomID(16)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invites[hashInvite(code)] = struct{}{}
	return code, s.persistLocked()
}

// Register consumes an invite and creates an account atomically. The invite
// is only consumed when the whole registration succeeds.
func (s *Store) Register(invite, username string, authPub, bundle []byte, prekeys [][]byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hashInvite(invite)
	if _, ok := s.invites[h]; !ok {
		return "", ErrInvalidInvite
	}
	if _, taken := s.byUsername[username]; taken {
		return "", ErrUsernameTaken
	}
	mailbox := randomID(16)
	acct := &Account{Username: username, MailboxID: mailbox, AuthPub: authPub, Bundle: bundle, OneTimePrekeys: prekeys}
	s.byMailbox[mailbox] = acct
	s.byUsername[username] = mailbox
	delete(s.invites, h)
	return mailbox, s.persistLocked()
}

// AuthKey returns the ECDSA P-256 public key (DER) for a mailbox.
func (s *Store) AuthKey(mailbox string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byMailbox[mailbox]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), a.AuthPub...), true
}

// Bundle returns the public bundle and pops one one-time prekey, if any.
func (s *Store) Bundle(username string) (mailbox string, bundle []byte, prekey []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mb, ok := s.byUsername[username]
	if !ok {
		return "", nil, nil, ErrNotFound
	}
	a := s.byMailbox[mb]
	if len(a.OneTimePrekeys) > 0 {
		prekey = a.OneTimePrekeys[0]
		a.OneTimePrekeys = a.OneTimePrekeys[1:]
	}
	return mb, append([]byte(nil), a.Bundle...), prekey, s.persistLocked()
}

func (s *Store) AddPrekeys(mailbox string, prekeys [][]byte, maxTotal int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byMailbox[mailbox]
	if !ok {
		return ErrNotFound
	}
	a.OneTimePrekeys = append(a.OneTimePrekeys, prekeys...)
	if len(a.OneTimePrekeys) > maxTotal {
		a.OneTimePrekeys = a.OneTimePrekeys[len(a.OneTimePrekeys)-maxTotal:]
	}
	return s.persistLocked()
}

// Enqueue stores opaque bytes for a mailbox until acknowledged or expired.
func (s *Store) Enqueue(mailbox string, body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byMailbox[mailbox]; !ok {
		return ErrNotFound
	}
	if len(s.queues[mailbox]) >= s.maxQueue {
		return ErrQueueFull
	}
	s.queues[mailbox] = append(s.queues[mailbox], envelope{
		id:      randomID(12),
		body:    append([]byte(nil), body...),
		expires: s.now().Add(s.ttl),
	})
	return nil
}

type Delivered struct {
	ID   string `json:"id"`
	Body []byte `json:"body"`
}

func (s *Store) Inbox(mailbox string) []Delivered {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Delivered{}
	now := s.now()
	for _, e := range s.queues[mailbox] {
		if now.Before(e.expires) {
			out = append(out, Delivered{ID: e.id, Body: append([]byte(nil), e.body...)})
		}
	}
	return out
}

func (s *Store) Ack(mailbox string, ids []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	drop := map[string]struct{}{}
	for _, id := range ids {
		drop[id] = struct{}{}
	}
	kept := s.queues[mailbox][:0]
	for _, e := range s.queues[mailbox] {
		if _, d := drop[e.id]; !d {
			kept = append(kept, e)
		}
	}
	if len(kept) == 0 {
		delete(s.queues, mailbox)
	} else {
		s.queues[mailbox] = kept
	}
}

func (s *Store) DeleteAccount(mailbox string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byMailbox[mailbox]
	if !ok {
		return ErrNotFound
	}
	delete(s.byUsername, a.Username)
	delete(s.byMailbox, mailbox)
	delete(s.queues, mailbox)
	return s.persistLocked()
}

// Purge removes expired envelopes and returns how many were dropped.
func (s *Store) Purge() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for mb, q := range s.queues {
		kept := q[:0]
		for _, e := range q {
			if now.Before(e.expires) {
				kept = append(kept, e)
			} else {
				n++
			}
		}
		if len(kept) == 0 {
			delete(s.queues, mb)
		} else {
			s.queues[mb] = kept
		}
	}
	return n
}

// persistLocked writes accounts + invite hashes atomically (0600). Queues are never written.
func (s *Store) persistLocked() error {
	if s.persistPath == "" {
		return nil
	}
	snap := snapshot{}
	for _, a := range s.byMailbox {
		snap.Accounts = append(snap.Accounts, a)
	}
	for h := range s.invites {
		snap.Invites = append(snap.Invites, h)
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	tmp := s.persistPath + ".tmp"
	if err := os.MkdirAll(filepath.Dir(s.persistPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.persistPath)
}

// Load restores accounts and invite hashes from the snapshot, if present.
func (s *Store) Load() error {
	if s.persistPath == "" {
		return nil
	}
	data, err := os.ReadFile(s.persistPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range snap.Accounts {
		s.byMailbox[a.MailboxID] = a
		s.byUsername[a.Username] = a.MailboxID
	}
	for _, h := range snap.Invites {
		s.invites[h] = struct{}{}
	}
	return nil
}

func constEq(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
