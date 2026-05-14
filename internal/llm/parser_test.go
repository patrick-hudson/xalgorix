package llm

import (
	"strings"
	"testing"
)

func TestParseAllFormats(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantFn string
		wantP  map[string]string
	}{
		{
			"standard equals",
			"<function=terminal_execute>\n<parameter=command>curl -I https://example.com</parameter>\n</function>",
			"terminal_execute",
			map[string]string{"command": "curl -I https://example.com"},
		},
		{
			"space variant",
			"<function=terminal_execute>\n<parameter command>curl -I https://example.com</parameter>\n</function>",
			"terminal_execute",
			map[string]string{"command": "curl -I https://example.com"},
		},
		{
			"name attr variant",
			"<function=python_action>\n<parameter name=\"code\">print(1)</parameter>\n</function>",
			"python_action",
			map[string]string{"code": "print(1)"},
		},
		{
			"finish space",
			"<function=finish>\n<parameter summary>assessment done</parameter>\n</function>",
			"finish",
			map[string]string{"summary": "assessment done"},
		},
		{
			"multi-line value",
			"<function=finish>\n<parameter=summary>line1\nline2\nline3</parameter>\n</function>",
			"finish",
			map[string]string{"summary": "line1\nline2\nline3"},
		},
		{
			"list_files space",
			"<function=list_files>\n<parameter path>/var/www</parameter>\n</function>",
			"list_files",
			map[string]string{"path": "/var/www"},
		},
		{
			"send_request multi space",
			"<function=send_request>\n<parameter method>GET</parameter>\n<parameter url>https://example.com</parameter>\n</function>",
			"send_request",
			map[string]string{"method": "GET", "url": "https://example.com"},
		},
		{
			"multi-line space value",
			"<function=finish>\n<parameter summary>line one\nline two\nline three</parameter>\n</function>",
			"finish",
			map[string]string{"summary": "line one\nline two\nline three"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := ParseToolCalls(tt.input)
			if len(calls) == 0 {
				t.Fatalf("no tool calls parsed")
			}
			if calls[0].Name != tt.wantFn {
				t.Errorf("fn = %q, want %q", calls[0].Name, tt.wantFn)
			}
			for k, v := range tt.wantP {
				got, ok := calls[0].Args[k]
				if !ok {
					t.Errorf("missing param %q (args=%v)", k, calls[0].Args)
				} else if got != v {
					t.Errorf("param[%s] = %q, want %q", k, got, v)
				}
			}
		})
	}
}

// TestFixIncomplete_SingleUnclosed exercises the original (pre-fix) case:
// one open <function=...> tag with no </function>. The repaired string
// must parse cleanly, the second return must be true (signals repair),
// and the resulting ToolCall must be flagged Truncated so the agent knows
// to nudge instead of dispatch.
func TestFixIncomplete_SingleUnclosed(t *testing.T) {
	in := "<function=terminal_execute>\n<parameter=command>id</parameter>"
	fixed, repaired := fixIncomplete(in)
	if !strings.Contains(fixed, "</function>") {
		t.Fatalf("fixIncomplete did not append closing tag: %q", fixed)
	}
	if !repaired {
		t.Error("fixIncomplete did not report a repair on an unclosed tag")
	}
	calls := ParseToolCalls(in) // parse the raw input — ParseToolCalls calls fixIncomplete itself
	if len(calls) != 1 || calls[0].Name != "terminal_execute" {
		t.Fatalf("expected 1 terminal_execute call, got %+v", calls)
	}
	if calls[0].Args["command"] != "id" {
		t.Errorf("command = %q, want id", calls[0].Args["command"])
	}
	if !calls[0].Truncated {
		t.Error("expected Truncated=true on the repaired call")
	}
}

// TestFixIncomplete_MultiBlockTrailingUnclosed is the regression case the
// review flagged: two open tags but only one close — the trailing one is
// the truncated one. The fix should still produce a parseable string AND
// only the trailing call should be flagged Truncated.
func TestFixIncomplete_MultiBlockTrailingUnclosed(t *testing.T) {
	in := "<function=list_files>\n<parameter=path>/etc</parameter>\n</function>\n" +
		"<function=terminal_execute>\n<parameter=command>id</parameter>"
	calls := ParseToolCalls(in)
	if len(calls) != 2 {
		t.Fatalf("expected 2 tool calls after repair, got %d", len(calls))
	}
	if calls[0].Name != "list_files" || calls[1].Name != "terminal_execute" {
		t.Errorf("call order wrong: %v", calls)
	}
	if calls[0].Truncated {
		t.Error("first call should NOT be flagged truncated (it was well-formed)")
	}
	if !calls[1].Truncated {
		t.Error("last call SHOULD be flagged truncated (it was the unclosed one)")
	}
}

// TestFixIncomplete_AlreadyBalanced must be a no-op when every open has a
// matching close — otherwise we'd double-close and break the parser.
func TestFixIncomplete_AlreadyBalanced(t *testing.T) {
	in := "<function=list_files>\n<parameter=path>/etc</parameter>\n</function>"
	got, repaired := fixIncomplete(in)
	if got != in {
		t.Errorf("expected no-op for balanced input, got %q", got)
	}
	if repaired {
		t.Error("repaired flag should be false for balanced input")
	}
}

// TestFixIncomplete_NoOpenTag must also be a no-op so plain prose isn't
// mangled into a fake tool call.
func TestFixIncomplete_NoOpenTag(t *testing.T) {
	in := "I will now run a command."
	got, repaired := fixIncomplete(in)
	if got != in {
		t.Errorf("expected no-op for non-tool prose, got %q", got)
	}
	if repaired {
		t.Error("repaired flag should be false for non-tool prose")
	}
}

// TestFixIncomplete_PartialEndTag handles the case where the model started
// emitting "</" but was cut off mid-tag. The fix completes it as
// "</function>".
func TestFixIncomplete_PartialEndTag(t *testing.T) {
	in := "<function=finish>\n<parameter=summary>done</parameter>\n</"
	fixed, repaired := fixIncomplete(in)
	if !strings.HasSuffix(fixed, "</function>") {
		t.Errorf("expected fixed string to end with </function>, got %q", fixed)
	}
	if !repaired {
		t.Error("expected repaired=true for a partial end tag")
	}
	calls := ParseToolCalls(in)
	if len(calls) != 1 || calls[0].Name != "finish" {
		t.Fatalf("expected 1 finish call, got %+v", calls)
	}
	if !calls[0].Truncated {
		t.Error("expected Truncated=true on the repaired call")
	}
}
