package jsonx

import (
	"encoding/json"
	"testing"
)

func TestParseRenderPreservesKeyOrderAndSeparators(t *testing.T) {
	in := `{"b":1,"a":[true,null],"c":{"d":"e"},"f":0.5}`
	got, err := Parse(in)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := `{"b": 1, "a": [true, null], "c": {"d": "e"}, "f": 0.5}`
	if rendered := Render(got); rendered != want {
		t.Fatalf("Render mismatch:\n got: %s\nwant: %s", rendered, want)
	}
}

func TestParseRejectsTrailingData(t *testing.T) {
	if _, err := Parse(`{"a":1} x`); err == nil {
		t.Fatal("expected error for trailing data")
	}
	if _, err := Parse(``); err == nil {
		t.Fatal("expected error for empty body")
	}
}

func TestParseDuplicateKeysKeepFirstPositionLastValue(t *testing.T) {
	got, err := Parse(`{"a":1,"b":2,"a":3}`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if rendered := Render(got); rendered != `{"a": 3, "b": 2}` {
		t.Fatalf("Render = %s", rendered)
	}
}

func TestParseScalars(t *testing.T) {
	got, err := Parse(`null`)
	if err != nil || got != nil {
		t.Fatalf("Parse(null) = %v, %v", got, err)
	}
	got, err = Parse(`"s"`)
	if err != nil || got != "s" {
		t.Fatalf("Parse(string) = %v, %v", got, err)
	}
	n, ok := gotNumber(t, `[7]`)
	if !ok || n.String() != "7" {
		t.Fatalf("number = %v, %v", n, ok)
	}
}

func gotNumber(t *testing.T, in string) (json.Number, bool) {
	t.Helper()
	got, err := Parse(in)
	if err != nil {
		t.Fatalf("Parse(%s): %v", in, err)
	}
	arr, ok := got.([]any)
	if !ok || len(arr) != 1 {
		return "", false
	}
	n, ok := arr[0].(json.Number)
	return n, ok
}

func TestObjectGet(t *testing.T) {
	got, err := Parse(`{"a":1,"b":"x"}`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	obj := got.(*Object)
	if v, ok := obj.Get("a"); !ok || v.(json.Number).String() != "1" {
		t.Fatalf("Get(a) = %v, %v", v, ok)
	}
	if _, ok := obj.Get("missing"); ok {
		t.Fatal("Get(missing) should be absent")
	}
}

func TestRepr(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, "None"},
		{true, "True"},
		{false, "False"},
		{json.Number("42"), "42"},
		{"plain", "'plain'"},
		{"a'b\\c", `'a\'b\\c'`},
		{"line\nnext\x1b", `'line\nnext\x1b'`},
		{[]any{}, "[]"},
		{[]any{"nacos", nil}, "['nacos', None]"},
	}
	for _, tc := range cases {
		if got := Repr(tc.in); got != tc.want {
			t.Fatalf("Repr(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestEscapeControls(t *testing.T) {
	if got := EscapeControls("a\nb\r\t\x1b\x7f"); got != `a\nb\r\t\u001b\u007f` {
		t.Fatalf("EscapeControls = %q", got)
	}
}
