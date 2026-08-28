// Package jsonx provides strict JSON parsing that preserves document key
// order, plus rendering and Python-style repr helpers used for output
// formatting.
package jsonx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Object is a parsed JSON object preserving document key order.
type Object struct {
	keys []string
	vals map[string]any
}

// Get returns the value for key and whether it was present. Duplicate keys
// keep the first position and the last value, matching Python's dict behavior.
func (o *Object) Get(key string) (any, bool) {
	v, ok := o.vals[key]
	return v, ok
}

// Parse decodes body as a single JSON value. Trailing garbage is rejected,
// mirroring json.loads.
func Parse(body string) (any, error) {
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing data after JSON value")
	}
	return v, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch delim := tok.(type) {
	case json.Delim:
		switch delim {
		case '{':
			obj := &Object{vals: make(map[string]any)}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, fmt.Errorf("non-string object key")
				}
				val, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				if _, dup := obj.vals[key]; !dup {
					obj.keys = append(obj.keys, key)
				}
				obj.vals[key] = val
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return arr, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter %q", delim)
		}
	default:
		return tok, nil
	}
}

// Render serializes a parsed value with ", " / ": " separators and raw UTF-8,
// matching json.dumps(..., ensure_ascii=False).
func Render(v any) string {
	var b strings.Builder
	renderValue(&b, v)
	return b.String()
}

func renderValue(b *strings.Builder, v any) {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		b.WriteString(t.String())
	case string:
		b.WriteString(renderString(t))
	case []any:
		b.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				b.WriteString(", ")
			}
			renderValue(b, item)
		}
		b.WriteByte(']')
	case *Object:
		b.WriteByte('{')
		for i, key := range t.keys {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(renderString(key))
			b.WriteString(": ")
			renderValue(b, t.vals[key])
		}
		b.WriteByte('}')
	default:
		b.WriteString(renderString(fmt.Sprint(t)))
	}
}

func renderString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return `""`
	}
	return strings.TrimRight(buf.String(), "\n")
}

// EscapeControls renders terminal control characters visibly while preserving
// printable Unicode. It is intended for untrusted values at output boundaries,
// not for values that will be parsed or sent back to a server.
func EscapeControls(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

func reprString(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\'':
			b.WriteString(`\'`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// Repr renders a value the way Python's repr would; used for output lines
// formatted with {!r} in the original tool's messages.
func Repr(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case bool:
		if t {
			return "True"
		}
		return "False"
	case json.Number:
		return t.String()
	case string:
		return reprString(t)
	case []any:
		parts := make([]string, len(t))
		for i, item := range t {
			parts[i] = Repr(item)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case *Object:
		parts := make([]string, 0, len(t.keys))
		for _, key := range t.keys {
			parts = append(parts, renderString(key)+": "+Repr(t.vals[key]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	default:
		return fmt.Sprint(t)
	}
}
