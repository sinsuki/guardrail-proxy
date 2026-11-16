// Package redact replaces PII in text with stable placeholders and can put
// the originals back. The mapping stays with the caller. Pattern matching
// misses names, street addresses, and obfuscated text.
package redact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Kind is the placeholder type, as in [EMAIL_1].
type Kind string

const (
	Email   Kind = "EMAIL"
	Phone   Kind = "PHONE"
	SSN     Kind = "SSN"
	Card    Kind = "CARD"
	Routing Kind = "ROUTING"
	Account Kind = "ACCOUNT"
	IBAN    Kind = "IBAN"
)

// Vault maps placeholders to the original text for one redaction pass.
// It is not safe for concurrent mutation.
type Vault struct {
	seq    map[Kind]int
	toTok  map[string]string
	toOrig map[string]string
}

func newVault() *Vault {
	return &Vault{
		seq:    make(map[Kind]int),
		toTok:  make(map[string]string),
		toOrig: make(map[string]string),
	}
}

// Counts reports how many distinct values were replaced for each kind.
func (v *Vault) Counts() map[Kind]int {
	if v == nil {
		return nil
	}
	out := make(map[Kind]int, len(v.seq))
	for k, n := range v.seq {
		out[k] = n
	}
	return out
}

// Redact returns text with PII replaced. The same value in this pass always
// gets the same placeholder.
func Redact(text string) (string, *Vault) {
	v := newVault()
	return redactInto(text, v), v
}

// Restore puts originals back in place of placeholders from v.
// Unknown placeholders are left as they are.
func (v *Vault) Restore(text string) string {
	if v == nil || len(v.toOrig) == 0 || !strings.Contains(text, "[") {
		return text
	}
	toks := make([]string, 0, len(v.toOrig))
	for tok := range v.toOrig {
		toks = append(toks, tok)
	}
	sort.Slice(toks, func(i, j int) bool { return len(toks[i]) > len(toks[j]) })
	for _, tok := range toks {
		text = strings.ReplaceAll(text, tok, v.toOrig[tok])
	}
	return text
}

// RedactJSON redacts string values and leaves numbers, keys, and structure in place.
func RedactJSON(body []byte) ([]byte, *Vault, error) {
	v := newVault()
	out, err := mapStrings(body, func(s string) string { return redactInto(s, v) })
	if err != nil {
		return nil, nil, err
	}
	return out, v, nil
}

// RestoreJSON restores string values in a JSON document.
func (v *Vault) RestoreJSON(body []byte) ([]byte, error) {
	if v == nil || len(v.toOrig) == 0 {
		return append([]byte(nil), body...), nil
	}
	return mapStrings(body, v.Restore)
}

func (v *Vault) token(kind Kind, original, text string) string {
	key := string(kind) + "\x00" + original
	if tok, ok := v.toTok[key]; ok {
		return tok
	}
	var tok string
	for {
		v.seq[kind]++
		tok = fmt.Sprintf("[%s_%d]", kind, v.seq[kind])
		// Skip a token that already appears in the source so a literal
		// [EMAIL_1] in the prompt is not confused with one we mint.
		if !strings.Contains(text, tok) {
			break
		}
		if v.seq[kind] > 10000 {
			break
		}
	}
	v.toTok[key] = tok
	v.toOrig[tok] = original
	return tok
}

type span struct {
	start int
	end   int
	kind  Kind
	prio  int
}

func redactInto(text string, v *Vault) string {
	spans := candidates(text)
	if len(spans) == 0 {
		return text
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		if spans[i].end != spans[j].end {
			return spans[i].end > spans[j].end
		}
		return spans[i].prio > spans[j].prio
	})
	var b strings.Builder
	b.Grow(len(text))
	last := 0
	covered := 0
	for _, sp := range spans {
		if sp.start < covered || sp.end > len(text) || sp.start < 0 {
			continue
		}
		b.WriteString(text[last:sp.start])
		b.WriteString(v.token(sp.kind, text[sp.start:sp.end], text))
		last = sp.end
		covered = sp.end
	}
	b.WriteString(text[last:])
	return b.String()
}

func candidates(s string) []span {
	var out []span
	out = append(out, emailSpans(s)...)
	out = append(out, phoneSpans(s)...)
	out = append(out, ssnSpans(s)...)
	out = append(out, cardSpans(s)...)
	out = append(out, routingSpans(s)...)
	out = append(out, accountSpans(s)...)
	out = append(out, ibanSpans(s)...)
	return out
}

var emailRE = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)+`)

func emailSpans(s string) []span {
	idx := emailRE.FindAllStringIndex(s, -1)
	out := make([]span, 0, len(idx))
	for _, pair := range idx {
		if !tldOK(s[pair[0]:pair[1]]) {
			continue
		}
		out = append(out, span{start: pair[0], end: pair[1], kind: Email, prio: 3})
	}
	return out
}

func tldOK(email string) bool {
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return false
	}
	dot := strings.LastIndexByte(email[at:], '.')
	if dot < 0 {
		return false
	}
	tld := email[at+dot+1:]
	if len(tld) < 2 {
		return false
	}
	for _, r := range tld {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

var phoneRE = regexp.MustCompile(`(?:\+\d{1,3}[\s.\-]?)?(?:\(\d{3}\)[\s.\-]?|\d{3}[\s.\-])\d{3}[\s.\-]\d{4}`)
var e164RE = regexp.MustCompile(`\+[1-9]\d{9,14}`)
var labeledPhoneRE = regexp.MustCompile(`(?i)\b(?:phone|tel|mobile|cell)\s*[:#]?\s*(\d{10})\b`)

func phoneSpans(s string) []span {
	var out []span
	for _, pair := range phoneRE.FindAllStringIndex(s, -1) {
		if !bounded(s, pair[0], pair[1]) {
			continue
		}
		if !nanp(digitsOnly(s[pair[0]:pair[1]])) {
			continue
		}
		out = append(out, span{start: pair[0], end: pair[1], kind: Phone, prio: 2})
	}
	for _, pair := range e164RE.FindAllStringIndex(s, -1) {
		if !bounded(s, pair[0], pair[1]) {
			continue
		}
		out = append(out, span{start: pair[0], end: pair[1], kind: Phone, prio: 2})
	}
	for _, m := range labeledPhoneRE.FindAllStringSubmatchIndex(s, -1) {
		if len(m) < 4 || m[2] < 0 {
			continue
		}
		if !nanp(s[m[2]:m[3]]) {
			continue
		}
		out = append(out, span{start: m[2], end: m[3], kind: Phone, prio: 2})
	}
	return out
}

func nanp(d string) bool {
	if len(d) == 11 && d[0] == '1' {
		d = d[1:]
	}
	if len(d) != 10 {
		return false
	}
	return d[0] >= '2' && d[3] >= '2'
}

var ssnRE = regexp.MustCompile(`\b(\d{3})-(\d{2})-(\d{4})\b`)
var ssnSpaceRE = regexp.MustCompile(`\b(\d{3}) (\d{2}) (\d{4})\b`)

func ssnSpans(s string) []span {
	var out []span
	for _, re := range []*regexp.Regexp{ssnRE, ssnSpaceRE} {
		for _, m := range re.FindAllStringSubmatchIndex(s, -1) {
			if !ssnOK(s[m[2]:m[3]], s[m[4]:m[5]], s[m[6]:m[7]]) {
				continue
			}
			out = append(out, span{start: m[0], end: m[1], kind: SSN, prio: 4})
		}
	}
	return out
}

func ssnOK(area, group, serial string) bool {
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}

func cardSpans(s string) []span {
	var out []span
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) || (i > 0 && isDigit(s[i-1])) {
			continue
		}
		end, ok := cardEnd(s, i)
		if !ok {
			continue
		}
		out = append(out, span{start: i, end: end, kind: Card, prio: 7})
		i = end - 1
	}
	return out
}

func cardEnd(s string, i int) (int, bool) {
	digits := make([]byte, 0, 19)
	j := i
	for j < len(s) {
		c := s[j]
		if isDigit(c) {
			digits = append(digits, c)
			j++
			if len(digits) > 19 {
				return 0, false
			}
			continue
		}
		if (c == ' ' || c == '-') && len(digits) > 0 && j+1 < len(s) && isDigit(s[j+1]) {
			j++
			continue
		}
		break
	}
	if len(digits) < 13 || len(digits) > 19 || allSame(digits) || !luhn(digits) {
		return 0, false
	}
	return j, true
}

func luhn(d []byte) bool {
	sum := 0
	alt := false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

func routingSpans(s string) []span {
	var out []span
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) || (i > 0 && isDigit(s[i-1])) {
			continue
		}
		if i+9 > len(s) {
			break
		}
		if i+9 < len(s) && isDigit(s[i+9]) {
			continue
		}
		chunk := s[i : i+9]
		if !abaOK(chunk) {
			continue
		}
		out = append(out, span{start: i, end: i + 9, kind: Routing, prio: 5})
		i += 8
	}
	return out
}

func abaOK(s string) bool {
	if len(s) != 9 {
		return false
	}
	d := make([]int, 9)
	for i := 0; i < 9; i++ {
		if !isDigit(s[i]) {
			return false
		}
		d[i] = int(s[i] - '0')
	}
	prefix := d[0]*10 + d[1]
	switch {
	case prefix <= 12, prefix >= 21 && prefix <= 32, prefix >= 61 && prefix <= 72, prefix == 80:
	default:
		return false
	}
	sum := 3*(d[0]+d[3]+d[6]) + 7*(d[1]+d[4]+d[7]) + (d[2] + d[5] + d[8])
	return sum%10 == 0
}

var accountRE = regexp.MustCompile(`(?i)\b(?:bank\s+)?(?:account|acct|checking|savings)(?:\s+(?:number|no\.?|#))?(?:\s+is)?\s*[:#]?\s*(\d{6,17})\b`)

func accountSpans(s string) []span {
	var out []span
	for _, m := range accountRE.FindAllStringSubmatchIndex(s, -1) {
		if len(m) < 4 || m[2] < 0 {
			continue
		}
		out = append(out, span{start: m[2], end: m[3], kind: Account, prio: 1})
	}
	return out
}

func ibanSpans(s string) []span {
	var out []span
	for i := 0; i < len(s); i++ {
		end, ok := ibanAt(s, i)
		if !ok {
			continue
		}
		out = append(out, span{start: i, end: end, kind: IBAN, prio: 6})
		i = end - 1
	}
	return out
}

func ibanAt(s string, i int) (int, bool) {
	if i+15 > len(s) || !isUpper(s[i]) || !isUpper(s[i+1]) || !isDigit(s[i+2]) || !isDigit(s[i+3]) {
		return 0, false
	}
	if i > 0 && isAlnum(s[i-1]) {
		return 0, false
	}
	j := i
	raw := make([]byte, 0, 34)
	for j < len(s) {
		c := s[j]
		if isAlnum(c) {
			raw = append(raw, c)
			j++
			if len(raw) > 34 {
				return 0, false
			}
			continue
		}
		if c == ' ' && len(raw) >= 4 && j+1 < len(s) && isAlnum(s[j+1]) {
			if len(raw) >= 15 && ibanOK(string(raw)) {
				break
			}
			j++
			continue
		}
		break
	}
	if len(raw) < 15 || !ibanOK(string(raw)) {
		return 0, false
	}
	return j, true
}

func ibanOK(s string) bool {
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	rearr := s[4:] + s[:4]
	mod := 0
	for i := 0; i < len(rearr); i++ {
		c := rearr[i]
		var n int
		switch {
		case c >= '0' && c <= '9':
			n = int(c - '0')
			mod = (mod*10 + n) % 97
		case c >= 'A' && c <= 'Z':
			n = int(c-'A') + 10
			mod = (mod*10 + n/10) % 97
			mod = (mod*10 + n%10) % 97
		default:
			return false
		}
	}
	return mod == 1
}

func bounded(s string, start, end int) bool {
	if start > 0 && isDigit(s[start-1]) {
		return false
	}
	if end < len(s) && isDigit(s[end]) {
		return false
	}
	return true
}

func digitsOnly(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func allSame(d []byte) bool {
	if len(d) == 0 {
		return true
	}
	for _, c := range d[1:] {
		if c != d[0] {
			return false
		}
	}
	return true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isAlnum(c byte) bool {
	return isDigit(c) || isUpper(c) || (c >= 'a' && c <= 'z')
}

func mapStrings(body []byte, fn func(string) string) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(body)))
	dec.UseNumber()
	var buf bytes.Buffer
	if err := writeValue(dec, &buf, fn); err != nil {
		return nil, err
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing json")
	}
	return buf.Bytes(), nil
}

func writeValue(dec *json.Decoder, buf *bytes.Buffer, fn func(string) string) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			buf.WriteByte('{')
			first := true
			for dec.More() {
				if !first {
					buf.WriteByte(',')
				}
				first = false
				keyTok, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyTok.(string)
				if !ok {
					return errors.New("json object key is not a string")
				}
				writeString(buf, key)
				buf.WriteByte(':')
				if err := writeValue(dec, buf, fn); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim('}') {
				return errors.New("json object did not end")
			}
			buf.WriteByte('}')
		case '[':
			buf.WriteByte('[')
			first := true
			for dec.More() {
				if !first {
					buf.WriteByte(',')
				}
				first = false
				if err := writeValue(dec, buf, fn); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim(']') {
				return errors.New("json array did not end")
			}
			buf.WriteByte(']')
		default:
			return errors.New("unexpected json delimiter")
		}
	case string:
		writeString(buf, fn(t))
	case json.Number:
		buf.WriteString(t.String())
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case nil:
		buf.WriteString("null")
	default:
		return fmt.Errorf("unexpected json token %T", tok)
	}
	return nil
}

func writeString(buf *bytes.Buffer, s string) {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	buf.Write(bytes.TrimRight(tmp.Bytes(), "\n"))
}
