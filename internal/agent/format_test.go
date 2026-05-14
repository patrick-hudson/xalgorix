package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// TestGetToolSuggestion_PythonShellHeredoc covers the Part-3 hint: when the
// LLM ran Python through a `python3 -c "..."` shell heredoc and bash
// interpolation mangled the source, we should detect the SyntaxError +
// `File "<string>"` traceback marker and tell the model to switch to the
// python_action tool. Sample stderr is the exact message from the live scan
// the user pasted.
func TestGetToolSuggestion_PythonShellHeredoc(t *testing.T) {
	stderr := `STDERR:
  File "<string>", line 7
    print(re.findall(r'src=["\'](.*?)["\'']', content))
                                          ^
SyntaxError: closing parenthesis ']' does not match opening parenthesis '('

[exit code: 1]`

	got := getToolSuggestion("terminal_execute", stderr)
	if got == "" {
		t.Fatal("expected a suggestion for Python shell-heredoc SyntaxError, got empty string")
	}
	for _, needle := range []string{
		"python_action",
		"shell-passed string",
		"<parameter=code>",
	} {
		if !strings.Contains(got, needle) {
			t.Errorf("suggestion missing %q\nfull suggestion:\n%s", needle, got)
		}
	}
}

// TestGetToolSuggestion_PythonShellHeredoc_StdinForm verifies the
// `File "<stdin>"` form of the traceback (piped stdin into python3) also
// triggers the same hint.
func TestGetToolSuggestion_PythonShellHeredoc_StdinForm(t *testing.T) {
	stderr := `  File "<stdin>", line 1
    some bad code
SyntaxError: invalid syntax`

	got := getToolSuggestion("terminal_execute", stderr)
	if !strings.Contains(got, "python_action") {
		t.Errorf("expected python_action suggestion for <stdin> traceback, got: %q", got)
	}
}

// TestGetToolSuggestion_GenericPlainSyntaxError must NOT fire the
// python_action hint for an unrelated SyntaxError (e.g. JS). The hint is
// only useful when we can confirm Python actually ran via shell — the
// File "<string>"/File "<stdin>" markers are that signal.
func TestGetToolSuggestion_GenericPlainSyntaxError(t *testing.T) {
	stderr := "SyntaxError: Unexpected token 'var'"
	got := getToolSuggestion("browser_action", stderr)
	if strings.Contains(got, "python_action") {
		t.Errorf("python_action hint should not fire on a generic SyntaxError without Python traceback markers; got: %q", got)
	}
}

// TestFormatToolResult_RecoverablePrefix asserts the softer error wording
// from Part 4. The model previously saw "Tool 'X' error:" which felt fatal;
// the new prefix tells it the failure is recoverable so it doesn't call
// `finish` on the first hiccup.
func TestFormatToolResult_RecoverablePrefix(t *testing.T) {
	msg := formatToolResult("terminal_execute", tools.Result{Error: "connection refused"})
	if !strings.Contains(msg, "Tool 'terminal_execute' returned an error (recoverable):") {
		t.Errorf("expected recoverable prefix, got: %q", msg)
	}
	if !strings.Contains(msg, "connection refused") {
		t.Errorf("expected raw error text preserved, got: %q", msg)
	}
}

// TestFormatToolResult_FallbackPreamble_OnUncategorizedError covers the
// happy path of Part 4: an error with no specific suggestion match still
// gets the universal recovery preamble so the LLM has guidance on what to
// do next.
func TestFormatToolResult_FallbackPreamble_OnUncategorizedError(t *testing.T) {
	// "connection refused" isn't matched by any error-class branch in
	// getToolSuggestion (the terminal/browser case has a "connection"
	// branch, but it returns a shorter network suggestion). So this needs
	// to be a truly uncategorized error.
	msg := formatToolResult("send_request", tools.Result{Error: "response body parse failed: invalid character 'x'"})
	for _, needle := range []string{
		"recoverable",
		"Re-emit the call with corrected arguments",
		"Try a different tool",
		"Do NOT call `finish`",
	} {
		if !strings.Contains(msg, needle) {
			t.Errorf("expected fallback preamble fragment %q in uncategorized-error result\nfull message:\n%s", needle, msg)
		}
	}
}

// TestFormatToolResult_NoDoubleHint asserts the fallback preamble does NOT
// fire when getToolSuggestion already returned a specific hint. The
// specific hints are more actionable; piling the generic preamble on top
// would just create noise.
func TestFormatToolResult_NoDoubleHint(t *testing.T) {
	msg := formatToolResult("value", tools.Result{Error: "unknown tool: value. Valid tools: terminal_execute, send_request"})
	if !strings.Contains(msg, "Tool calls must use <function=TOOL_NAME>") {
		t.Errorf("expected specific unknown-tool suggestion, got: %q", msg)
	}
	// Fallback preamble must NOT also appear.
	if strings.Contains(msg, "Pick ONE of:") {
		t.Errorf("specific suggestion fired but fallback preamble also appeared (double hint):\n%s", msg)
	}
}

// TestFormatToolResult_SuccessWithOutput must not gain any of the
// recovery wording on the success path.
func TestFormatToolResult_SuccessWithOutput(t *testing.T) {
	msg := formatToolResult("terminal_execute", tools.Result{Output: "hello world"})
	if !strings.Contains(msg, "Tool 'terminal_execute' result:") {
		t.Errorf("expected success-result prefix, got: %q", msg)
	}
	for _, forbidden := range []string{"recoverable", "Recovery:", "Do NOT call `finish`"} {
		if strings.Contains(msg, forbidden) {
			t.Errorf("success-path message must not contain recovery wording %q\nfull message:\n%s", forbidden, msg)
		}
	}
}

// TestFormatToolResult_SuccessNoOutput preserves the "completed (no output)"
// path so silent tools (e.g. notes_save) still report cleanly.
func TestFormatToolResult_SuccessNoOutput(t *testing.T) {
	msg := formatToolResult("notes_save", tools.Result{})
	if !strings.Contains(msg, "Tool 'notes_save' completed successfully (no output)") {
		t.Errorf("expected no-output success message, got: %q", msg)
	}
}
