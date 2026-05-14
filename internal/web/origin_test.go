package web

import (
	"net/http/httptest"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// TestIsOriginAllowed covers the WebSocket / CSRF Origin allowlist matrix.
// The same helper is used by both upgrader.CheckOrigin and isCSRFSafe, so
// a single table here exercises both call sites.
func TestIsOriginAllowed(t *testing.T) {
	type tc struct {
		name           string
		host           string   // r.Host
		origin         string   // Origin header (or Referer in CSRF)
		trustedOrigins []string // cfg.TrustedOrigins
		want           bool
	}

	cases := []tc{
		// --- Empty origin (loopback / curl / dev tooling) → allowed.
		{
			name:   "empty origin allowed",
			host:   "x.local",
			origin: "",
			want:   true,
		},

		// --- Same-host shortcut (preserves historical behavior).
		{
			name:   "matching origin allowed without allowlist",
			host:   "x.local",
			origin: "http://x.local",
			want:   true,
		},
		{
			name:   "matching origin with port allowed",
			host:   "x.local:8080",
			origin: "http://x.local:8080",
			want:   true,
		},

		// --- No allowlist + mismatched host → reject.
		{
			name:   "mismatched origin rejected",
			host:   "x.local",
			origin: "http://attacker.tld",
			want:   false,
		},
		{
			name:   "port-mismatched origin rejected",
			host:   "x.local:1337",
			origin: "http://x.local:9999",
			want:   false,
		},

		// --- Allowlist exact match.
		{
			name:           "allowlist exact host scheme match allowed",
			host:           "internal-alb.amazonaws.com",
			origin:         "https://app.example.com",
			trustedOrigins: []string{"https://app.example.com"},
			want:           true,
		},
		{
			name:           "allowlist exact host wrong scheme rejected",
			host:           "internal-alb.amazonaws.com",
			origin:         "http://app.example.com",
			trustedOrigins: []string{"https://app.example.com"},
			want:           false,
		},
		{
			name:           "allowlist with port matches",
			host:           "internal-alb.amazonaws.com",
			origin:         "https://app.example.com:443",
			trustedOrigins: []string{"https://app.example.com:443"},
			want:           true,
		},

		// --- Allowlist wildcard suffix.
		{
			name:           "wildcard subdomain matches",
			host:           "internal-alb.amazonaws.com",
			origin:         "https://api.example.com",
			trustedOrigins: []string{"https://*.example.com"},
			want:           true,
		},
		{
			name:           "wildcard subdomain matches deeper subdomain",
			host:           "internal-alb.amazonaws.com",
			origin:         "https://foo.bar.example.com",
			trustedOrigins: []string{"https://*.example.com"},
			want:           true,
		},
		{
			name:           "wildcard apex domain rejected",
			host:           "internal-alb.amazonaws.com",
			origin:         "https://example.com",
			trustedOrigins: []string{"https://*.example.com"},
			want:           false,
		},
		{
			name:           "wildcard cross-domain rejected",
			host:           "internal-alb.amazonaws.com",
			origin:         "https://example.com.attacker.tld",
			trustedOrigins: []string{"https://*.example.com"},
			want:           false,
		},
		{
			name:           "wildcard wrong scheme rejected",
			host:           "internal-alb.amazonaws.com",
			origin:         "http://api.example.com",
			trustedOrigins: []string{"https://*.example.com"},
			want:           false,
		},

		// --- Multiple allowlist entries — first match wins.
		{
			name:   "multi-entry allowlist matches second entry",
			host:   "internal-alb.amazonaws.com",
			origin: "https://admin.example.com",
			trustedOrigins: []string{
				"https://app.example.com",
				"https://admin.example.com",
			},
			want: true,
		},
		{
			name:   "multi-entry allowlist no match rejected",
			host:   "internal-alb.amazonaws.com",
			origin: "https://other.tld",
			trustedOrigins: []string{
				"https://app.example.com",
				"https://admin.example.com",
			},
			want: false,
		},

		// --- Malformed input — never match.
		{
			name:   "unparseable origin rejected",
			host:   "x.local",
			origin: "::not-a-url::",
			want:   false,
		},
		{
			name:   "origin missing host rejected",
			host:   "x.local",
			origin: "https:///path",
			want:   false,
		},
		{
			name:           "garbage allowlist entries skipped, real one still matches",
			host:           "internal-alb.amazonaws.com",
			origin:         "https://app.example.com",
			trustedOrigins: []string{"::garbage::", "", "https://app.example.com"},
			want:           true,
		},

		// --- Case insensitivity for host matching against allowlist.
		{
			name:           "allowlist case-insensitive on host",
			host:           "internal-alb.amazonaws.com",
			origin:         "https://APP.example.com",
			trustedOrigins: []string{"https://app.example.com"},
			want:           true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/ws", nil)
			r.Host = c.host
			cfg := &config.Config{TrustedOrigins: c.trustedOrigins}
			if got := isOriginAllowed(r, c.origin, cfg); got != c.want {
				t.Errorf("isOriginAllowed(host=%q, origin=%q, allowlist=%v) = %v, want %v",
					c.host, c.origin, c.trustedOrigins, got, c.want)
			}
		})
	}
}

// TestIsOriginAllowed_NilCfg confirms the helper tolerates a nil config —
// the call sites pass config.Get() which always returns non-nil, but a
// defensive nil check keeps the contract robust.
func TestIsOriginAllowed_NilCfg(t *testing.T) {
	r := httptest.NewRequest("POST", "/ws", nil)
	r.Host = "x.local"

	if !isOriginAllowed(r, "", nil) {
		t.Error("empty origin with nil cfg should be allowed")
	}
	if !isOriginAllowed(r, "http://x.local", nil) {
		t.Error("matching host with nil cfg should be allowed")
	}
	if isOriginAllowed(r, "http://attacker.tld", nil) {
		t.Error("mismatched host with nil cfg should be rejected")
	}
}

// TestIsCSRFSafe_TrustedOrigins is the integration-level regression for the
// "CloudFront rewrites Host" scenario the trusted-origins allowlist exists
// to fix. The browser's Origin header still points at the CloudFront
// domain, but r.Host has been rewritten to the ALB DNS by the proxy.
func TestIsCSRFSafe_TrustedOrigins(t *testing.T) {
	cfg := &config.Config{
		TrustedOrigins: []string{"https://app.cloudfront.net"},
	}

	r := httptest.NewRequest("POST", "/api/scan", nil)
	r.Host = "internal-alb.us-west-2.elb.amazonaws.com"
	r.Header.Set("Origin", "https://app.cloudfront.net")

	if !isCSRFSafe(r, cfg) {
		t.Fatal("isCSRFSafe should accept Origin in TrustedOrigins even when r.Host differs")
	}

	// Without the allowlist the same request must still be rejected.
	if isCSRFSafe(r, &config.Config{}) {
		t.Fatal("isCSRFSafe must reject mismatched Origin when TrustedOrigins is empty")
	}
}
