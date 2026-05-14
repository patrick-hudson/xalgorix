// Package python provides the python_action tool via subprocess.
package python

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/terminal"
)

// missingModuleRegex captures the bare import name from CPython's
// `ModuleNotFoundError: No module named 'X'` formatted error. CPython uses
// single quotes; some pyodide-style runtimes use double quotes — accept both.
var missingModuleRegex = regexp.MustCompile(`ModuleNotFoundError: No module named ['"]([A-Za-z0-9_.\-]+)['"]`)

// pythonModuleSafeName enforces "looks like a normal PyPI distribution name"
// before we pass it to `pip install`. Rejects shell metacharacters by
// construction.
var pythonModuleSafeName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._\-]*$`)

// importToDistribution maps common import-time module names to their
// canonical PyPI distribution name. `pip install <import-name>` only
// works when the two happen to coincide, which they often don't.
var importToDistribution = map[string]string{
	"bs4":           "beautifulsoup4",
	"BeautifulSoup": "beautifulsoup4",
	"Crypto":        "pycryptodome",
	"cv2":           "opencv-python",
	"PIL":           "Pillow",
	"yaml":          "pyyaml",
	"jwt":           "pyjwt",
	"OpenSSL":       "pyopenssl",
	"dateutil":      "python-dateutil",
	"magic":         "python-magic",
	"socks":         "pysocks",
	"websocket":     "websocket-client",
}

// Register adds the python_action tool to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "python_action",
		Description: "Execute Python code in a subprocess. Python 3 must be installed.",
		Parameters: []tools.Parameter{
			{Name: "code", Description: "Python code to execute", Required: true},
			{Name: "timeout", Description: "Timeout in seconds (default: 1800 = 30 min)", Required: false},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			return executePythonForContext(r.GetScanContextID(), args)
		},
	})
}

func executePython(args map[string]string) (tools.Result, error) {
	return executePythonForContext(scanctx.Default().ID, args)
}

func executePythonForContext(contextID string, args map[string]string) (tools.Result, error) {
	if strings.TrimSpace(contextID) == "" {
		contextID = scanctx.Default().ID
	}

	code := args["code"]
	if code == "" {
		return tools.Result{}, fmt.Errorf("code is required")
	}

	timeoutSec := 1800 // 30 minutes — exploit scripts can run long
	if t := args["timeout"]; t != "" {
		parsed, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return tools.Result{Error: fmt.Sprintf("invalid timeout value '%s': must be a number in seconds", t)}, nil
		}
		timeoutSec = parsed
		if timeoutSec <= 0 {
			timeoutSec = 1800
		}
		if timeoutSec > 7200 { // Cap at 2 hours
			timeoutSec = 7200
		}
	}

	// Find python3
	pythonBin := "python3"
	if _, err := exec.LookPath(pythonBin); err != nil {
		pythonBin = "python"
		if _, err := exec.LookPath(pythonBin); err != nil {
			return tools.Result{}, fmt.Errorf("python not found. Install python3")
		}
	}

	workDir := terminal.GetWorkDirForContext(contextID)
	if workDir == "" {
		workDir = config.Get().Workspace
	}
	workDir = filepath.Clean(workDir)
	preparePythonWorkspace(workDir)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	res := runPython(ctx, pythonBin, code, workDir, contextID, timeoutSec)

	// Auto-install fallback: ModuleNotFoundError → pip install --user <X>
	// + one retry. Only when the operator has opted into auto-install
	// (gated the same way terminal_execute's installer is). Capped at one
	// retry so we never enter an install → retry → install loop.
	if res.err != nil && config.Get().AllowAutoInstall && ctx.Err() != context.DeadlineExceeded {
		if mod := extractMissingModule(res.stderr); mod != "" {
			dist := pipDistributionFor(mod)
			if pythonModuleSafeName.MatchString(dist) {
				installOut, installErr := pipInstallUserModule(pythonBin, workDir, dist)
				if installErr == nil {
					retry := runPython(ctx, pythonBin, code, workDir, contextID, timeoutSec)
					retry.installNote = fmt.Sprintf("[auto-installed %s via pip --user]\n", dist)
					res = retry
					_ = installOut // discard pip's stdout, the header is enough
				}
			}
		}
	}

	return tools.Result{Output: res.formatted()}, nil
}

// pythonRunResult captures one python3 invocation's output, normalized so
// the caller can re-run and replace it without re-doing buffer accounting.
type pythonRunResult struct {
	stdout      string
	stdoutTrunc bool
	stderr      string
	stderrTrunc bool
	err         error
	timedOut    bool
	exitCode    int
	timeoutSec  int
	installNote string // prepended to formatted() when set
}

// formatted renders the result the way the original executePythonForContext
// historically did (stdout block + "STDERR:" block + exit/timeout footer).
func (r pythonRunResult) formatted() string {
	var b strings.Builder
	if r.installNote != "" {
		b.WriteString(r.installNote)
	}
	if r.stdout != "" {
		b.WriteString(r.stdout)
		if r.stdoutTrunc {
			b.WriteString("\n... [OUTPUT TRUNCATED: exceeded 1MB]")
		}
	}
	if r.stderr != "" {
		if b.Len() > 0 && r.installNote == "" {
			b.WriteString("\n")
		} else if r.installNote != "" && b.Len() > len(r.installNote) {
			b.WriteString("\n")
		}
		b.WriteString("STDERR:\n")
		b.WriteString(r.stderr)
		if r.stderrTrunc {
			b.WriteString("\n... [STDERR TRUNCATED: exceeded 512KB]")
		}
	}
	if r.err != nil {
		if r.timedOut {
			b.WriteString(fmt.Sprintf("\n[TIMEOUT: exceeded %ds]", r.timeoutSec))
		} else {
			b.WriteString(fmt.Sprintf("\n[exit code: %d]", r.exitCode))
		}
	}
	if b.Len() == 0 || (r.installNote != "" && b.Len() == len(r.installNote)) {
		b.WriteString("(no output)")
	}
	return b.String()
}

// runPython runs one `python3 -c <code>` invocation under a sub-context
// derived from parentCtx (so the parent's deadline still bounds total
// runtime across retries) and captures stdout/stderr with the same buffer
// caps the original tool used. Each run gets its own cancel func so the
// watchdog / stop-scan path can kill the in-flight process.
func runPython(parentCtx context.Context, pythonBin, code, workDir, contextID string, timeoutSec int) pythonRunResult {
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	cmd := exec.CommandContext(ctx, pythonBin, "-c", code)
	cmd.Dir = workDir
	cmd.Env = pythonWorkspaceEnv(workDir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout := newLimitedBuffer(1024 * 1024)
	stderr := newLimitedBuffer(512 * 1024)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return pythonRunResult{
			stderr:     fmt.Sprintf("Failed to start python process: %v", err),
			err:        err,
			timeoutSec: timeoutSec,
		}
	}
	terminal.ApplyProcessLimits(cmd, true)

	cleanCode := code
	if len(cleanCode) > 100 {
		cleanCode = cleanCode[:100] + "..."
	}
	terminal.TrackProcessForContext(contextID, cmd, cancel, "python: "+strings.ReplaceAll(cleanCode, "\n", " "))
	defer terminal.UntrackProcessForContext(contextID, cmd)

	err := cmd.Wait()

	out := stdout.String()
	if len(out) > 15000 {
		out = out[:15000] + "\n... [OUTPUT TRUNCATED]"
	}
	errOut := stderr.String()
	if len(errOut) > 5000 {
		errOut = errOut[:5000] + "\n... [TRUNCATED]"
	}

	res := pythonRunResult{
		stdout:      out,
		stdoutTrunc: stdout.Truncated(),
		stderr:      errOut,
		stderrTrunc: stderr.Truncated(),
		err:         err,
		timeoutSec:  timeoutSec,
	}
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			res.timedOut = true
		} else if exitErr, ok := err.(*exec.ExitError); ok {
			res.exitCode = exitErr.ExitCode()
		}
	}
	return res
}

// extractMissingModule pulls the bare module name out of a CPython
// `ModuleNotFoundError` traceback. Returns "" when no match is found OR
// when the captured string fails the safe-name check (defensive — keeps
// adversarial stderr from steering a pip install).
func extractMissingModule(stderr string) string {
	m := missingModuleRegex.FindStringSubmatch(stderr)
	if len(m) < 2 {
		return ""
	}
	name := strings.TrimSpace(m[1])
	if !pythonModuleSafeName.MatchString(name) {
		return ""
	}
	return name
}

// pipDistributionFor maps a Python import name to its PyPI distribution
// name where the two differ. Falls back to the import name unchanged.
func pipDistributionFor(importName string) string {
	if dist, ok := importToDistribution[importName]; ok {
		return dist
	}
	return importName
}

// pipInstallUserModule runs `<pythonBin> -m pip install --user <dist>` with
// a tight timeout. Using the resolved interpreter via `-m pip` guarantees
// the install lands in whatever Python the script actually runs against —
// closes the gap between the base image's 3.12 and apt's 3.11 on this
// sandbox.
func pipInstallUserModule(pythonBin, workDir, dist string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, pythonBin, "-m", "pip", "install", "--user", "--no-input", "--disable-pip-version-check", dist)
	cmd.Dir = workDir
	cmd.Env = pythonWorkspaceEnv(workDir)

	out, err := cmd.CombinedOutput()
	return string(out), err
}

func preparePythonWorkspace(workDir string) {
	_ = os.MkdirAll(filepath.Join(workDir, ".tmp"), 0o755)
	_ = os.MkdirAll(filepath.Join(workDir, ".cache"), 0o755)
	_ = os.MkdirAll(filepath.Join(workDir, ".config"), 0o755)
	_ = os.MkdirAll(filepath.Join(workDir, ".local", "share"), 0o755)
}

func pythonWorkspaceEnv(workDir string) []string {
	replace := map[string]bool{
		"HOME":                    true,
		"TMPDIR":                  true,
		"XDG_CACHE_HOME":          true,
		"XDG_CONFIG_HOME":         true,
		"XDG_DATA_HOME":           true,
		"XALGORIX_WORKSPACE":      true,
		"PYTHONDONTWRITEBYTECODE": true,
	}
	env := make([]string, 0, len(os.Environ())+7)
	for _, kv := range os.Environ() {
		key, _, ok := strings.Cut(kv, "=")
		if ok && replace[key] {
			continue
		}
		env = append(env, kv)
	}
	return append(env,
		"HOME="+workDir,
		"TMPDIR="+filepath.Join(workDir, ".tmp"),
		"XDG_CACHE_HOME="+filepath.Join(workDir, ".cache"),
		"XDG_CONFIG_HOME="+filepath.Join(workDir, ".config"),
		"XDG_DATA_HOME="+filepath.Join(workDir, ".local", "share"),
		"XALGORIX_WORKSPACE="+workDir,
		"PYTHONDONTWRITEBYTECODE=1",
	)
}

type limitedBuffer struct {
	bytes.Buffer
	limit     int
	truncated bool
}

func newLimitedBuffer(limit int) *limitedBuffer {
	return &limitedBuffer{limit: limit}
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 || b.Len() >= b.limit {
		b.truncated = true
		return len(p), nil
	}
	remaining := b.limit - b.Len()
	if len(p) > remaining {
		b.truncated = true
		_, _ = b.Buffer.Write(p[:remaining])
		return len(p), nil
	}
	_, _ = b.Buffer.Write(p)
	return len(p), nil
}

func (b *limitedBuffer) Truncated() bool {
	return b.truncated
}
