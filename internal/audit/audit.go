// Package audit is an append-only hash-chained log. Each line is JSON, carries
// the SHA-256 of the previous line, and is signed with Ed25519. The private
// key stays on disk outside the repo.
package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
)

const (
	Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

	KindToolCall        = "tool_call"
	KindSchema          = "schema"
	KindDecision        = "decision"
	KindApprovalRequest = "approval_request"
	KindApprovalResult  = "approval_result"
	KindRedaction       = "redaction"
	KindForward         = "forward"
)

// ChainError is the first problem found in a log.
// Line is 1-based. Zero means the problem is the tip, not a line.
type ChainError struct {
	Line   int
	Reason string
}

func (e *ChainError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("entry %d: %s", e.Line, e.Reason)
	}
	return e.Reason
}

// Log appends signed entries. It is safe for concurrent use.
type Log struct {
	mu   sync.Mutex
	path string
	f    *os.File
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	seq  uint64
	prev string
}

// GenerateKey writes a new Ed25519 seed to privPath (mode 0600) and the
// public key to pubPath (mode 0644). Both files are hex, one line.
func GenerateKey(privPath, pubPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := writeHex(privPath, priv.Seed(), 0600); err != nil {
		return err
	}
	return writeHex(pubPath, pub, 0644)
}

// LoadPrivate reads a hex seed or a hex private key.
func LoadPrivate(path string) (ed25519.PrivateKey, error) {
	b, err := readHex(path)
	if err != nil {
		return nil, err
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	default:
		return nil, fmt.Errorf("audit private key has length %d", len(b))
	}
}

// LoadPublic reads a hex public key.
func LoadPublic(path string) (ed25519.PublicKey, error) {
	b, err := readHex(path)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("audit public key has length %d", len(b))
	}
	return ed25519.PublicKey(b), nil
}

// Open opens or creates the log and resumes from the last signed line.
func Open(path string, priv ed25519.PrivateKey) (*Log, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("audit private key is invalid")
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	l := &Log{path: path, f: f, priv: priv, pub: priv.Public().(ed25519.PublicKey), prev: Genesis}
	if err := flock(f); err != nil {
		f.Close()
		return nil, err
	}
	err = l.reload()
	unflock(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return l, nil
}

// Close flushes and closes the log.
func (l *Log) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := l.f.Sync()
	if cErr := l.f.Close(); err == nil {
		err = cErr
	}
	l.f = nil
	return err
}

// Append signs one event and adds it to the end of the log.
func (l *Log) Append(kind string, payload any) error {
	if kind == "" {
		return errors.New("audit event kind is empty")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := flock(l.f); err != nil {
		return err
	}
	defer unflock(l.f)
	if err := l.reload(); err != nil {
		return err
	}
	raw, err := l.encode(l.seq+1, time.Now().UTC().Format(time.RFC3339Nano), kind, l.prev, payload)
	if err != nil {
		return err
	}
	if _, err := l.f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	if _, err := l.f.Write(raw); err != nil {
		return err
	}
	if err := l.f.Sync(); err != nil {
		return err
	}
	l.seq++
	l.prev = hashBytes(raw)
	return l.writeTip()
}

// Verify checks signatures, the hash chain, and the signed tip.
// It returns the number of entries when the log is intact.
func Verify(logPath, pubPath string) (int, error) {
	pub, err := LoadPublic(pubPath)
	if err != nil {
		return 0, err
	}
	f, err := os.Open(logPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		return 0, err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	prev := Genesis
	var last []byte
	n := 0
	for sc.Scan() {
		n++
		line := sc.Bytes()
		raw := append(append([]byte(nil), line...), '\n')
		if err := checkLine(pub, raw, prev, uint64(n)); err != nil {
			var ce *ChainError
			if errors.As(err, &ce) {
				ce.Line = n
			}
			return n, err
		}
		prev = hashBytes(raw)
		last = append([]byte(nil), raw...)
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	if n == 0 {
		if _, err := os.Stat(tipPath(logPath)); err == nil {
			return 0, &ChainError{Reason: "tip exists for an empty log"}
		}
		return 0, nil
	}
	if err := checkTip(pub, logPath, uint64(n), hashBytes(last)); err != nil {
		return n, err
	}
	return n, nil
}

func (l *Log) reload() error {
	st, err := l.f.Stat()
	if err != nil {
		return err
	}
	if st.Size() == 0 {
		l.seq = 0
		l.prev = Genesis
		return nil
	}
	raw, err := readLastLine(l.f, st.Size())
	if err != nil {
		return err
	}
	if !verifyRaw(l.pub, raw) {
		return errors.New("audit log tail: bad signature")
	}
	meta, err := metaOf(raw)
	if err != nil {
		return err
	}
	l.seq = meta.Seq
	l.prev = hashBytes(raw)
	return nil
}

func (l *Log) encode(seq uint64, when, kind, prev string, payload any) ([]byte, error) {
	body, err := marshal(payload)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 || string(body) == "null" {
		body = []byte("{}")
	}
	prefix := fmt.Sprintf(`{"seq":%d,"time":%s,"kind":%s,"prev":%s,"payload":%s`,
		seq, jstr(when), jstr(kind), jstr(prev), body)
	sig := ed25519.Sign(l.priv, []byte(prefix))
	line := make([]byte, 0, len(prefix)+len(sig)+16)
	line = append(line, prefix...)
	line = append(line, `,"sig":"`...)
	line = append(line, base64.StdEncoding.EncodeToString(sig)...)
	line = append(line, '"', '}', '\n')
	return line, nil
}

func (l *Log) writeTip() error {
	prefix := fmt.Sprintf(`{"seq":%d,"hash":%s`, l.seq, jstr(l.prev))
	sig := ed25519.Sign(l.priv, []byte(prefix))
	var buf bytes.Buffer
	buf.WriteString(prefix)
	buf.WriteString(`,"sig":"`)
	buf.WriteString(base64.StdEncoding.EncodeToString(sig))
	buf.WriteString("\"}\n")
	tmp := tipPath(l.path) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, tipPath(l.path))
}

func checkLine(pub ed25519.PublicKey, raw []byte, wantPrev string, wantSeq uint64) error {
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return &ChainError{Reason: "line does not end with a newline"}
	}
	if !verifyRaw(pub, raw) {
		return &ChainError{Reason: "bad signature"}
	}
	meta, err := metaOf(raw)
	if err != nil {
		return &ChainError{Reason: "malformed entry"}
	}
	if wantSeq != 0 && meta.Seq != wantSeq {
		return &ChainError{Reason: fmt.Sprintf("sequence %d, want %d", meta.Seq, wantSeq)}
	}
	if wantPrev != "" && meta.Prev != wantPrev {
		return &ChainError{Reason: "prev hash mismatch"}
	}
	return nil
}

func verifyRaw(pub ed25519.PublicKey, raw []byte) bool {
	prefix, sig, err := splitSig(bytes.TrimRight(raw, "\n"))
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, prefix, sig)
}

func metaOf(raw []byte) (struct {
	Seq  uint64 `json:"seq"`
	Prev string `json:"prev"`
	Kind string `json:"kind"`
}, error) {
	var meta struct {
		Seq  uint64 `json:"seq"`
		Prev string `json:"prev"`
		Kind string `json:"kind"`
	}
	prefix, _, err := splitSig(bytes.TrimRight(raw, "\n"))
	if err != nil {
		return meta, err
	}
	err = json.Unmarshal(append(append([]byte(nil), prefix...), '}'), &meta)
	return meta, err
}

func checkTip(pub ed25519.PublicKey, logPath string, seq uint64, hash string) error {
	b, err := os.ReadFile(tipPath(logPath))
	if err != nil {
		return &ChainError{Reason: "tip is missing"}
	}
	b = bytes.TrimRight(b, "\n")
	prefix, sig, err := splitSig(b)
	if err != nil || !ed25519.Verify(pub, prefix, sig) {
		return &ChainError{Reason: "tip has a bad signature"}
	}
	var tip struct {
		Seq  uint64 `json:"seq"`
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(append(append([]byte(nil), prefix...), '}'), &tip); err != nil {
		return &ChainError{Reason: "tip is malformed"}
	}
	if tip.Seq > seq {
		return &ChainError{Reason: fmt.Sprintf("log truncated: tip seq %d, log seq %d", tip.Seq, seq)}
	}
	if tip.Seq < seq {
		return &ChainError{Reason: fmt.Sprintf("tip is behind the log: tip seq %d, log seq %d", tip.Seq, seq)}
	}
	if tip.Hash != hash {
		return &ChainError{Reason: "tip hash does not match the last entry"}
	}
	return nil
}

func splitSig(line []byte) (prefix, sig []byte, err error) {
	const marker = `,"sig":"`
	i := bytes.LastIndex(line, []byte(marker))
	if i < 0 || !bytes.HasSuffix(line, []byte(`"}`)) {
		return nil, nil, errors.New("missing signature")
	}
	b64 := line[i+len(marker) : len(line)-2]
	sig, err = base64.StdEncoding.DecodeString(string(b64))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, nil, errors.New("bad signature encoding")
	}
	return line[:i], sig, nil
}

func readLastLine(f *os.File, size int64) ([]byte, error) {
	n := int64(256 * 1024)
	if size < n {
		n = size
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, size-n); err != nil && err != io.EOF {
		return nil, err
	}
	if buf[len(buf)-1] != '\n' {
		return nil, errors.New("audit log does not end with a newline")
	}
	buf = buf[:len(buf)-1]
	i := bytes.LastIndexByte(buf, '\n')
	line := append([]byte(nil), buf[i+1:]...)
	return append(line, '\n'), nil
}

func tipPath(logPath string) string { return logPath + ".tip" }

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func marshal(v any) ([]byte, error) {
	if v == nil {
		return []byte("{}"), nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func jstr(s string) string {
	b, _ := marshal(s)
	return string(b)
}

func writeHex(path string, b []byte, mode os.FileMode) error {
	return os.WriteFile(path, []byte(hex.EncodeToString(b)+"\n"), mode)
}

func readHex(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(string(bytes.TrimSpace(b)))
}

func flock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

func unflock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
