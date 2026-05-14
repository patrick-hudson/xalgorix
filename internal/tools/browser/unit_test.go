package browser

import (
	"strings"
	"testing"

	"github.com/go-rod/rod/lib/proto"
)

// ── parseSelector ──

func TestParseSelector_SemanticID(t *testing.T) {
	tests := []struct{ in, want string }{
		{"@e1", `[data-xalgo-id="e1"]`},
		{"@e999", `[data-xalgo-id="e999"]`},
	}
	for _, tc := range tests {
		if got := parseSelector(tc.in); got != tc.want {
			t.Errorf("parseSelector(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseSelector_PlainCSS(t *testing.T) {
	tests := []string{"#login-btn", ".form-input", "button", "div > span", ""}
	for _, s := range tests {
		if got := parseSelector(s); got != s {
			t.Errorf("parseSelector(%q) = %q, want unchanged", s, got)
		}
	}
}

// ── truncate ──

func TestTruncate(t *testing.T) {
	tests := []struct {
		in     string
		max    int
		want   string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 5, "hello..."},
		{"", 5, ""},
	}
	for _, tc := range tests {
		if got := truncate(tc.in, tc.max); got != tc.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}
}

// ── formatExpiry ──

func TestFormatExpiry_Zero(t *testing.T) {
	if got := formatExpiry(0); got != "Session" {
		t.Errorf("formatExpiry(0) = %q, want Session", got)
	}
}

func TestFormatExpiry_Valid(t *testing.T) {
	// 1700000000 epoch seconds → 2023-11-14
	ts := proto.TimeSinceEpoch(1700000000)
	got := formatExpiry(ts)
	if got == "Session" || got == "" {
		t.Errorf("formatExpiry(1700000000) = %q, want a date string", got)
	}
}

// ── ExtractVerificationURL ──

func TestExtractVerificationURL(t *testing.T) {
	tests := []struct {
		name, body, want string
	}{
		{"confirm link", "Click here: https://app.com/confirm?token=abc123def456ghij7890", "https://app.com/confirm?token=abc123def456ghij7890"},
		{"verify path", "Verify: https://example.com/verify/longtoken12345678901234567890", "https://example.com/verify/longtoken12345678901234567890"},
		{"reset link", "Reset: https://site.com/reset?t=abcdefghijklmnopqrstuvwx", "https://site.com/reset?t=abcdefghijklmnopqrstuvwx"},
		{"no match", "No links here, just text.", ""},
		{"trailing dot", "Click https://app.com/verify?t=token123456789012345678.", "https://app.com/verify?t=token123456789012345678"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractVerificationURL(tc.body)
			if got != tc.want {
				t.Errorf("ExtractVerificationURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ── Command dispatch ──

func TestDispatch_UnknownCommand(t *testing.T) {
	ctxID := "test-dispatch-unknown"
	_, err := browserActionWithContext(ctxID, map[string]string{"command": "nonexistent"})
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
	if got := err.Error(); !contains(got, "unknown browser action") {
		t.Errorf("error = %q, want 'unknown browser action'", got)
	}
}

func TestDispatch_EmptyCommand(t *testing.T) {
	ctxID := "test-dispatch-empty"
	_, err := browserActionWithContext(ctxID, map[string]string{"command": ""})
	if err == nil {
		t.Fatal("expected error for empty command")
	}
}

// ── browserStore isolation ──

func TestBrowserStore_Isolation(t *testing.T) {
	a := getBrowserStoreByID("iso-a")
	b := getBrowserStoreByID("iso-b")
	if a == b {
		t.Error("different IDs returned the same store")
	}
}

func TestBrowserStore_SameID(t *testing.T) {
	a := getBrowserStoreByID("iso-same")
	b := getBrowserStoreByID("iso-same")
	if a != b {
		t.Error("same ID returned different stores")
	}
}

func TestBrowserStore_Initialization(t *testing.T) {
	s := getBrowserStoreByID("iso-init-check")
	if s.browser != nil {
		t.Error("new store should have nil browser")
	}
	if s.page != nil {
		t.Error("new store should have nil page")
	}
	if len(s.pages) != 0 {
		t.Error("new store should have empty pages map")
	}
	if s.nextTab != 1 {
		t.Errorf("new store nextTab = %d, want 1", s.nextTab)
	}
}

// ── isJSEvalError / formatJSEvalHint ──

func TestIsJSEvalError_Recognizes(t *testing.T) {
	cases := []string{
		"eval js error: SyntaxError: Unexpected token 'var' <nil>",
		"eval js error: ReferenceError: foo is not defined",
		"eval js error: TypeError: Cannot read properties of null",
		"eval js error: RangeError: Maximum call stack size exceeded",
		"eval js error: EvalError: some message",
		"eval js error: URIError: malformed URI",
	}
	for _, in := range cases {
		if !isJSEvalError(in) {
			t.Errorf("isJSEvalError(%q) = false, want true", in)
		}
	}
}

func TestIsJSEvalError_Rejects(t *testing.T) {
	cases := []string{
		"browser not launched",
		"context deadline exceeded",
		"navigation timeout: net::ERR_TIMED_OUT",
		"",
	}
	for _, in := range cases {
		if isJSEvalError(in) {
			t.Errorf("isJSEvalError(%q) = true, want false", in)
		}
	}
}

func TestFormatJSEvalHint_StripsNilTailAndIncludesGuidance(t *testing.T) {
	raw := "eval js error: SyntaxError: Unexpected token 'var' <nil>"
	out := formatJSEvalHint(raw)
	// Trailing "<nil>" must be gone — that's the go-rod chain artifact
	// confusing the LLM in its conversation history.
	if strings.Contains(out, "<nil>") {
		t.Errorf("formatJSEvalHint output still contains '<nil>': %q", out)
	}
	// The original error text minus the <nil> should still be visible.
	if !strings.Contains(out, "SyntaxError: Unexpected token 'var'") {
		t.Errorf("formatJSEvalHint output missing original error: %q", out)
	}
	// IIFE guidance and the two common-fix bullets are load-bearing for the
	// LLM's self-recovery; lock them in.
	for _, needle := range []string{
		"recoverable",
		"page.Eval expects an expression",
		"(() => { const x = document.title; return x; })()",
		"Replace bare `var x = 5; x`",
		"Replace `console.log(...)`",
		"For DOM queries, return the value",
	} {
		if !strings.Contains(out, needle) {
			t.Errorf("formatJSEvalHint output missing guidance %q\nfull output:\n%s", needle, out)
		}
	}
}

// helper
func contains(s, sub string) bool {
	return len(s) >= len(sub) && containsStr(s, sub)
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
