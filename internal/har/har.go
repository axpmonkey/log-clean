// Package har sanitizes HAR (HTTP Archive) files as JSON rather than as text
// lines. A whole HAR is often a single line, and line-based processing can't
// tell a header name from its value, a cookie from a query parameter, or a
// response body from request metadata. This package walks the structure:
//
//   - Credential headers (Authorization, Cookie, Set-Cookie,
//     Proxy-Authorization, CSRF/XSRF/token/API-key/secret/session headers)
//     and every cookie value are redacted whole.
//   - queryString / postData.params values are redacted when the parameter
//     name is a credential (ticket, code, state, password, ...).
//   - Response bodies (response.content.text) are dropped unless
//     Options.KeepBodies is set, in which case they are scanned.
//   - Timings, sizes, status, methods, header names and other non-sensitive
//     fields are left untouched.
//   - Every other string value goes through the caller's scan function (the
//     normal detector walk), so URLs get host-only tokenization, IPs and
//     hostnames are tokenized, and so on.
//
// Object key order and number formatting are preserved, so the output stays
// diffable against the input and is always valid JSON.
package har

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"sas-log-sanitize/internal/detect"
)

// Redacted is the placeholder for a value removed wholesale.
const Redacted = "SECRET_REDACTED"

// bodyRemovedComment marks a response body dropped by default.
const bodyRemovedComment = "response body removed by sas-log-sanitize (use --keep-har-bodies to keep)"

// Options controls HAR handling.
type Options struct {
	// KeepBodies keeps response bodies (scanned) instead of dropping them.
	KeepBodies bool
}

var harSniff = regexp.MustCompile(`^\s*\{\s*"log"\s*:`)

// Looks reports whether a file should be handled as a HAR: a .har extension,
// or a .json file whose content starts with a top-level "log" key.
//
// A gzip-compressed HAR ("x.har.gz") is judged by its inner name; head must
// then be decompressed bytes.
func Looks(path string, head []byte) bool {
	name := strings.ToLower(path)
	name = strings.TrimSuffix(name, ".gz")
	switch filepath.Ext(name) {
	case ".har":
		return true
	case ".json":
		return harSniff.Match(bytes.TrimPrefix(head, []byte("\xEF\xBB\xBF")))
	}
	return false
}

// Transform is TransformStream over in-memory data.
func Transform(data []byte, opts Options, scan func(string) string) ([]byte, int, error) {
	var out bytes.Buffer
	n, err := TransformStream(bytes.NewReader(data), &out, opts, scan)
	if err != nil {
		return nil, 0, err
	}
	return out.Bytes(), n, nil
}

// TransformStream reads a HAR from r, applies the rules above, passes every
// remaining string value through scan, and writes the result to w as
// indented JSON (one value per line, so audit lines stay short). It returns
// the number of values this package redacted or dropped itself.
//
// The document is streamed token by token: memory is bounded by the largest
// single string, not by the file -- multi-GB HARs work. Only small
// name/value list entries (headers, cookies, queryString, params) are
// parsed whole, because their rules need the name before the value; a
// response body that is dropped is skipped without being kept.
//
// scan receives whole string values (possibly multi-line). Traversal order
// is deterministic, so a Pass 1 call (scan registers values, w discards) and
// a Pass 2 call (scan replaces them) see the same strings in the same order.
// On a parse error, part of the output may already have been written; the
// pipeline runs Pass 1 first and only streams Pass 2 for files Pass 1
// parsed successfully.
func TransformStream(r io.Reader, w io.Writer, opts Options, scan func(string) string) (int, error) {
	br := bufio.NewReaderSize(r, 64*1024)
	bw := bufio.NewWriterSize(w, 64*1024)
	if head, _ := br.Peek(3); bytes.Equal(head, []byte("\xEF\xBB\xBF")) {
		br.Discard(3)
		bw.WriteString("\xEF\xBB\xBF")
	}
	dec := json.NewDecoder(br)
	dec.UseNumber()
	t := &transformer{opts: opts, scan: scan, dec: dec, w: bw}

	tok, err := dec.Token()
	if err != nil {
		return 0, fmt.Errorf("parsing HAR: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return 0, fmt.Errorf("parsing HAR: top-level value is not an object")
	}
	if err := t.streamObject(nil, 0); err != nil {
		return 0, fmt.Errorf("parsing HAR: %w", err)
	}
	if !t.sawLog {
		return 0, fmt.Errorf("parsing HAR: no top-level \"log\" object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return 0, fmt.Errorf("parsing HAR: trailing data after top-level value")
	}
	bw.WriteByte('\n')
	if err := bw.Flush(); err != nil {
		return 0, err
	}
	return t.redactions, nil
}

// harIndent is the output indentation unit.
const harIndent = "  "

func (t *transformer) newline(depth int) {
	t.w.WriteByte('\n')
	for i := 0; i < depth; i++ {
		t.w.WriteString(harIndent)
	}
}

// listKeys are arrays of name/value entries, parsed whole per entry.
var listKeys = map[string]bool{"headers": true, "cookies": true, "queryString": true, "params": true}

// streamObject streams the members of an object whose '{' was just read.
func (t *transformer) streamObject(path []string, depth int) error {
	t.w.WriteByte('{')
	inBody := last(path, 1) == "content" && last(path, 2) == "response" && !t.opts.KeepBodies
	n, dropped := 0, false
	for t.dec.More() {
		kt, err := t.dec.Token()
		if err != nil {
			return err
		}
		key, ok := kt.(string)
		if !ok {
			return fmt.Errorf("object key is %T", kt)
		}
		if depth == 0 && key == "log" {
			t.sawLog = true
		}
		// Drop the response body (and its encoding) without keeping it.
		if inBody && (key == "text" || key == "encoding") {
			if _, err := parseValue(t.dec); err != nil {
				return err
			}
			if key == "text" {
				dropped = true
				t.redactions++
			}
			continue
		}
		if n > 0 {
			t.w.WriteByte(',')
		}
		n++
		t.newline(depth + 1)
		writeString(t.w, key)
		t.w.WriteString(": ")
		if err := t.streamValue(append(path[:len(path):len(path)], key), depth+1); err != nil {
			return err
		}
	}
	if dropped {
		if n > 0 {
			t.w.WriteByte(',')
		}
		n++
		t.newline(depth + 1)
		writeString(t.w, "comment")
		t.w.WriteString(": ")
		writeString(t.w, bodyRemovedComment)
	}
	if _, err := t.dec.Token(); err != nil { // '}'
		return err
	}
	if n > 0 {
		t.newline(depth)
	}
	t.w.WriteByte('}')
	return nil
}

// streamValue streams the next value, found at path (path's last element is
// the value's own key; array elements share their array's key).
func (t *transformer) streamValue(path []string, depth int) error {
	tok, err := t.dec.Token()
	if err != nil {
		return err
	}
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			if listKeys[last(path, 1)] {
				// A name/value entry: small, and its rules need the name
				// before the value, so it is parsed whole.
				o, err := parseObjectBody(t.dec)
				if err != nil {
					return err
				}
				t.walkObject(o, path)
				return encodeValue(t.w, o, harIndent, depth)
			}
			return t.streamObject(path, depth)
		case '[':
			t.w.WriteByte('[')
			n := 0
			for t.dec.More() {
				if n > 0 {
					t.w.WriteByte(',')
				}
				n++
				t.newline(depth + 1)
				if err := t.streamValue(path, depth+1); err != nil {
					return err
				}
				// Each HAR entry goes out as soon as it is done.
				if last(path, 1) == "entries" {
					if err := t.w.Flush(); err != nil {
						return err
					}
				}
			}
			if _, err := t.dec.Token(); err != nil { // ']'
				return err
			}
			if n > 0 {
				t.newline(depth)
			}
			t.w.WriteByte(']')
			return nil
		}
		return fmt.Errorf("unexpected delimiter %q", v)
	case string:
		if v != "" && !untouchedKeys[last(path, 1)] {
			v = t.scan(v)
		}
		writeString(t.w, v)
		return nil
	default:
		return encodeValue(t.w, v, harIndent, depth)
	}
}

// ---- rules -----------------------------------------------------------------

// sensitiveHeader matches header names whose value is a credential and is
// redacted whole, never scanned.
var sensitiveHeader = regexp.MustCompile(`(?i)^(?:proxy-)?authorization$|^(?:set-)?cookie$|csrf|xsrf|token|api-?key|secret|session|^x-auth`)

// untouchedKeys hold non-sensitive strings that are never scanned: changing
// them would only damage analysis (methods, versions, timestamps, MIME
// types, priorities, connection IDs, ...).
var untouchedKeys = map[string]bool{
	"method": true, "httpVersion": true, "startedDateTime": true, "mimeType": true,
	"expires": true, "encoding": true, "contentType": true, "pageref": true,
	"_resourceType": true, "_priority": true, "connection": true, "type": true,
	"version": true, "id": true,
}

type transformer struct {
	opts       Options
	scan       func(string) string
	redactions int

	dec    *json.Decoder
	w      *bufio.Writer
	sawLog bool
}

// walk transforms v in place. path is the chain of object keys leading to
// v (array indexes are not recorded, so elements share their array's key).
func (t *transformer) walk(v any, path []string) {
	switch n := v.(type) {
	case *object:
		t.walkObject(n, path)
	case []any:
		for _, el := range n {
			t.walk(el, path)
		}
	}
}

func last(path []string, i int) string {
	if len(path) < i {
		return ""
	}
	return path[len(path)-i]
}

func (t *transformer) walkObject(o *object, path []string) {
	// response.content: drop the body unless asked to keep it.
	if last(path, 1) == "content" && last(path, 2) == "response" && !t.opts.KeepBodies {
		if o.get("text") != nil {
			o.del("text")
			o.del("encoding")
			o.set("comment", bodyRemovedComment)
			t.redactions++
		}
	}

	// name/value list entries: headers, cookies, queryString, params.
	switch last(path, 1) {
	case "headers":
		t.nameValue(o, path, func(name string) bool { return sensitiveHeader.MatchString(name) })
		return
	case "cookies":
		t.nameValue(o, path, func(string) bool { return true })
		return
	case "queryString", "params":
		t.nameValue(o, path, detect.IsSecretParamName)
		return
	}

	for i, k := range o.keys {
		t.field(o, i, k, path)
	}
}

// nameValue handles one {"name":..., "value":...} list entry: the name is
// kept as is; the value is redacted whole when redact(name) says so, and
// scanned otherwise. Other fields (cookie path/domain, fileName, ...) are
// handled like any field.
func (t *transformer) nameValue(o *object, path []string, redact func(string) bool) {
	name, _ := o.get("name").(string)
	for i, k := range o.keys {
		switch k {
		case "name":
			continue
		case "value":
			if s, ok := o.vals[i].(string); ok {
				if redact(name) {
					if s != "" {
						o.vals[i] = Redacted
						t.redactions++
					}
				} else {
					o.vals[i] = t.scan(s)
				}
			}
		default:
			t.field(o, i, k, path)
		}
	}
}

func (t *transformer) field(o *object, i int, k string, path []string) {
	switch v := o.vals[i].(type) {
	case string:
		if !untouchedKeys[k] && v != "" {
			o.vals[i] = t.scan(v)
		}
	case *object, []any:
		t.walk(v, append(path[:len(path):len(path)], k))
	}
}

// ---- order-preserving JSON -------------------------------------------------

// object is a JSON object that remembers key order.
type object struct {
	keys []string
	vals []any
}

func (o *object) get(k string) any {
	for i, key := range o.keys {
		if key == k {
			return o.vals[i]
		}
	}
	return nil
}

func (o *object) set(k string, v any) {
	for i, key := range o.keys {
		if key == k {
			o.vals[i] = v
			return
		}
	}
	o.keys = append(o.keys, k)
	o.vals = append(o.vals, v)
}

func (o *object) del(k string) {
	for i, key := range o.keys {
		if key == k {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			o.vals = append(o.vals[:i], o.vals[i+1:]...)
			return
		}
	}
}

// parseValue reads one JSON value. Values are *object, []any, string,
// json.Number, bool or nil.
func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch d := tok.(type) {
	case json.Delim:
		switch d {
		case '{':
			return parseObjectBody(dec)
		case '[':
			arr := []any{}
			for dec.More() {
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			if _, err := dec.Token(); err != nil { // ']'
				return nil, err
			}
			return arr, nil
		}
		return nil, fmt.Errorf("unexpected delimiter %q", d)
	default:
		return tok, nil // string, json.Number, bool, nil
	}
}

// parseObjectBody reads an object's members after its '{' was consumed.
func parseObjectBody(dec *json.Decoder) (*object, error) {
	o := &object{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := kt.(string)
		if !ok {
			return nil, fmt.Errorf("object key is %T", kt)
		}
		v, err := parseValue(dec)
		if err != nil {
			return nil, err
		}
		o.keys = append(o.keys, key)
		o.vals = append(o.vals, v)
	}
	if _, err := dec.Token(); err != nil { // '}'
		return nil, err
	}
	return o, nil
}

// byteWriter is satisfied by *bytes.Buffer and *bufio.Writer.
type byteWriter interface {
	io.Writer
	io.ByteWriter
	io.StringWriter
}

// encodeValue writes v as JSON. indent "" writes compact JSON.
func encodeValue(w byteWriter, v any, indent string, depth int) error {
	nl := func(d int) {
		if indent != "" {
			w.WriteByte('\n')
			w.WriteString(strings.Repeat(indent, d))
		}
	}
	sep := ":"
	if indent != "" {
		sep = ": "
	}
	switch n := v.(type) {
	case *object:
		w.WriteByte('{')
		for i, k := range n.keys {
			if i > 0 {
				w.WriteByte(',')
			}
			nl(depth + 1)
			writeString(w, k)
			w.WriteString(sep)
			if err := encodeValue(w, n.vals[i], indent, depth+1); err != nil {
				return err
			}
		}
		if len(n.keys) > 0 {
			nl(depth)
		}
		w.WriteByte('}')
	case []any:
		w.WriteByte('[')
		for i, el := range n {
			if i > 0 {
				w.WriteByte(',')
			}
			nl(depth + 1)
			if err := encodeValue(w, el, indent, depth+1); err != nil {
				return err
			}
		}
		if len(n) > 0 {
			nl(depth)
		}
		w.WriteByte(']')
	case string:
		writeString(w, n)
	case json.Number:
		w.WriteString(n.String())
	case bool:
		if n {
			w.WriteString("true")
		} else {
			w.WriteString("false")
		}
	case nil:
		w.WriteString("null")
	default:
		return fmt.Errorf("unexpected JSON value %T", v)
	}
	return nil
}

func writeString(w byteWriter, s string) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a Go string always encodes
	w.Write(bytes.TrimSuffix(b.Bytes(), []byte("\n")))
}
