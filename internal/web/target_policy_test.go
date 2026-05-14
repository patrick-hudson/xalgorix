package web

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// TestTargetPolicy_Decide exercises the layered precedence documented at
// the top of (*targetPolicy).Decide. Cases are grouped by which layer the
// expected outcome should come from.
func TestTargetPolicy_Decide(t *testing.T) {
	type tc struct {
		name         string
		cfg          config.Config
		target       string
		wantAllowed  bool
		wantReason   string // empty when wantAllowed=true
	}

	cases := []tc{
		// ── Layer 2: hard rules. Always blocked, regardless of cfg. ──
		{
			name:        "loopback IPv4 hard-blocked even with allow-private",
			cfg:         config.Config{TargetAllowPrivateNetworks: true},
			target:      "127.0.0.1",
			wantAllowed: false,
			wantReason:  BlockReasonLoopback,
		},
		{
			name:        "loopback hostname hard-blocked",
			cfg:         config.Config{TargetAllowPrivateNetworks: true},
			target:      "localhost",
			wantAllowed: false,
			wantReason:  BlockReasonContainerHost,
		},
		{
			name:        "loopback IPv6 hard-blocked",
			cfg:         config.Config{TargetAllowPrivateNetworks: true},
			target:      "::1",
			wantAllowed: false,
			wantReason:  BlockReasonLoopback,
		},
		{
			name:        "EC2 IMDS link-local hard-blocked even with allow-private",
			cfg:         config.Config{TargetAllowPrivateNetworks: true},
			target:      "169.254.169.254",
			wantAllowed: false,
			wantReason:  BlockReasonLinkLocal,
		},
		{
			name:        "ECS task metadata link-local hard-blocked",
			cfg:         config.Config{TargetAllowPrivateNetworks: true},
			target:      "169.254.170.2",
			wantAllowed: false,
			wantReason:  BlockReasonLinkLocal,
		},
		{
			name:        "unspecified IPv4 hard-blocked",
			cfg:         config.Config{TargetAllowPrivateNetworks: true},
			target:      "0.0.0.0",
			wantAllowed: false,
			wantReason:  BlockReasonUnspecified,
		},
		{
			name:        "host.docker.internal hostname hard-blocked",
			cfg:         config.Config{TargetAllowPrivateNetworks: true},
			target:      "host.docker.internal",
			wantAllowed: false,
			wantReason:  BlockReasonContainerHost,
		},
		{
			name:        "metadata.google.internal hostname hard-blocked",
			cfg:         config.Config{TargetAllowPrivateNetworks: true},
			target:      "metadata.google.internal",
			wantAllowed: false,
			wantReason:  BlockReasonContainerHost,
		},

		// ── Layer 5: RFC 1918 / ULA gated by AllowPrivateNetworks. ──
		{
			name:        "RFC1918 10/8 blocked when allow-private off",
			cfg:         config.Config{TargetAllowPrivateNetworks: false},
			target:      "10.42.0.1",
			wantAllowed: false,
			wantReason:  BlockReasonPrivateDisabled,
		},
		{
			name:        "RFC1918 10/8 allowed when allow-private on",
			cfg:         config.Config{TargetAllowPrivateNetworks: true},
			target:      "10.42.0.1",
			wantAllowed: true,
		},
		{
			name:        "RFC1918 172.16/12 blocked when allow-private off",
			cfg:         config.Config{TargetAllowPrivateNetworks: false},
			target:      "172.20.5.5",
			wantAllowed: false,
			wantReason:  BlockReasonPrivateDisabled,
		},
		{
			name:        "RFC1918 172.16/12 allowed when allow-private on",
			cfg:         config.Config{TargetAllowPrivateNetworks: true},
			target:      "172.20.5.5",
			wantAllowed: true,
		},
		{
			name:        "RFC1918 192.168/16 blocked when allow-private off",
			cfg:         config.Config{TargetAllowPrivateNetworks: false},
			target:      "192.168.1.1",
			wantAllowed: false,
			wantReason:  BlockReasonPrivateDisabled,
		},
		{
			name:        "RFC1918 192.168/16 allowed when allow-private on",
			cfg:         config.Config{TargetAllowPrivateNetworks: true},
			target:      "192.168.1.1",
			wantAllowed: true,
		},
		{
			name:        "IPv6 ULA blocked when allow-private off",
			cfg:         config.Config{TargetAllowPrivateNetworks: false},
			target:      "fd12:3456:789a::1",
			wantAllowed: false,
			wantReason:  BlockReasonPrivateDisabled,
		},
		{
			name:        "IPv6 ULA allowed when allow-private on",
			cfg:         config.Config{TargetAllowPrivateNetworks: true},
			target:      "fd12:3456:789a::1",
			wantAllowed: true,
		},

		// ── Layer 3: operator blocklist. Beats private toggle. ──
		{
			name: "operator CIDR blocklist beats allow-private",
			cfg: config.Config{
				TargetAllowPrivateNetworks: true,
				TargetBlocklist:            []string{"10.99.0.0/16"},
			},
			target:      "10.99.5.5",
			wantAllowed: false,
			wantReason:  BlockReasonOperatorBlock,
		},
		{
			name: "operator hostname blocklist beats allow-private",
			cfg: config.Config{
				TargetAllowPrivateNetworks: true,
				TargetBlocklist:            []string{"evil.example.com"},
			},
			target:      "evil.example.com",
			wantAllowed: false,
			wantReason:  BlockReasonOperatorBlock,
		},
		{
			name: "operator bare IP blocklist beats allow-private",
			cfg: config.Config{
				TargetAllowPrivateNetworks: true,
				TargetBlocklist:            []string{"10.0.0.5"},
			},
			target:      "10.0.0.5",
			wantAllowed: false,
			wantReason:  BlockReasonOperatorBlock,
		},

		// ── Layer 4: operator CIDR allowlist. Overrides private-network block. ──
		{
			name: "operator CIDR allowlist allows when allow-private off",
			cfg: config.Config{
				TargetAllowPrivateNetworks: false,
				TargetAllowlist:            []string{"10.42.0.0/16"},
			},
			target:      "10.42.5.5",
			wantAllowed: true,
		},
		{
			name: "operator CIDR allowlist does NOT bypass hard rule",
			cfg: config.Config{
				TargetAllowPrivateNetworks: false,
				TargetAllowlist:            []string{"127.0.0.0/8"},
			},
			target:      "127.0.0.1",
			wantAllowed: false,
			wantReason:  BlockReasonLoopback,
		},

		// ── Layer 1: operator hostname allowlist. ──
		{
			name: "operator hostname allowlist allows literal host",
			cfg: config.Config{
				TargetAllowPrivateNetworks: false,
				TargetAllowlist:            []string{"internal.corp.example"},
			},
			target:      "internal.corp.example",
			wantAllowed: true,
		},
		{
			name: "operator hostname allowlist does NOT bypass hard rule",
			cfg: config.Config{
				TargetAllowlist: []string{"localhost"},
			},
			target:      "localhost",
			wantAllowed: false,
			wantReason:  BlockReasonContainerHost,
		},

		// ── Layer 6: public address always allowed. ──
		{
			name:        "public IPv4 allowed by default",
			cfg:         config.Config{},
			target:      "8.8.8.8",
			wantAllowed: true,
		},
		{
			name:        "public hostname allowed by default",
			cfg:         config.Config{},
			target:      "example.com",
			wantAllowed: true,
		},
		{
			name:        "public hostname with scheme and port allowed",
			cfg:         config.Config{},
			target:      "https://example.com:8443/api",
			wantAllowed: true,
		},

		// ── Empty / malformed input. ──
		{
			name:        "empty string is allowed (upstream trim drops it)",
			cfg:         config.Config{},
			target:      "",
			wantAllowed: true,
		},
		{
			name:        "whitespace-only is allowed (upstream trim drops it)",
			cfg:         config.Config{},
			target:      "   ",
			wantAllowed: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newTargetPolicyFromConfig(&c.cfg)
			gotAllowed, gotReason := p.Decide(c.target)
			if gotAllowed != c.wantAllowed {
				t.Errorf("allowed = %v, want %v (reason=%q)", gotAllowed, c.wantAllowed, gotReason)
			}
			if !c.wantAllowed && gotReason != c.wantReason {
				t.Errorf("reason = %q, want %q", gotReason, c.wantReason)
			}
			if c.wantAllowed && gotReason != "" {
				t.Errorf("reason = %q for allowed case, want empty", gotReason)
			}
		})
	}
}

// TestTargetPolicy_NilCfg confirms newTargetPolicyFromConfig tolerates a
// nil config — the policy is still usable (everything not hard-blocked
// passes) so the call site doesn't have to nil-check.
func TestTargetPolicy_NilCfg(t *testing.T) {
	p := newTargetPolicyFromConfig(nil)
	if p == nil {
		t.Fatal("newTargetPolicyFromConfig(nil) returned nil")
	}
	if allowed, _ := p.Decide("8.8.8.8"); !allowed {
		t.Error("public IP should be allowed under nil-cfg policy")
	}
	if allowed, reason := p.Decide("127.0.0.1"); allowed || reason != BlockReasonLoopback {
		t.Errorf("loopback should still be blocked under nil-cfg policy: allowed=%v reason=%q", allowed, reason)
	}
}

// TestParseCIDROrHost covers the operator-list parser used by both
// allowlist and blocklist construction. Bare IPs are promoted to /32 (or
// /128) so an operator can drop a single address into the env var
// without needing to remember the suffix.
func TestParseCIDROrHost(t *testing.T) {
	type tc struct {
		raw      string
		wantCIDR string // empty when entry is a hostname
		wantHost string // empty when entry is a CIDR
		wantOK   bool
	}
	cases := []tc{
		{raw: "10.0.0.0/8", wantCIDR: "10.0.0.0/8", wantOK: true},
		{raw: "192.168.1.1", wantCIDR: "192.168.1.1/32", wantOK: true},
		{raw: "fd12::1", wantCIDR: "fd12::1/128", wantOK: true},
		{raw: "Example.COM", wantHost: "example.com", wantOK: true},
		{raw: "internal.corp", wantHost: "internal.corp", wantOK: true},
		{raw: "", wantOK: false},
		{raw: "  ", wantOK: false},
		{raw: "has spaces.example.com", wantOK: false},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			cidr, host, ok := parseCIDROrHost(c.raw)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if !ok {
				return
			}
			if c.wantCIDR != "" {
				if cidr == nil {
					t.Fatalf("expected CIDR %q, got hostname %q", c.wantCIDR, host)
				}
				if got := cidr.String(); got != c.wantCIDR {
					t.Errorf("cidr = %q, want %q", got, c.wantCIDR)
				}
			}
			if c.wantHost != "" {
				if host != c.wantHost {
					t.Errorf("host = %q, want %q", host, c.wantHost)
				}
				if cidr != nil {
					t.Errorf("expected hostname-only result, got cidr=%v", cidr)
				}
			}
		})
	}
}

// TestNormalizeHost peels scheme + port off various target formats. The
// intake handler accepts URLs, host:port pairs, bare hosts, and bare IPs;
// they all need to land in the same normalized form for policy lookup.
func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"example.com", "example.com", true},
		{"https://example.com", "example.com", true},
		{"https://example.com:8443/path?q=1", "example.com", true},
		{"example.com:8443", "example.com", true},
		{"127.0.0.1:80", "127.0.0.1", true},
		{"http://[::1]:8080", "::1", true},
		{"", "", false},
		{"   ", "", false},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, ok := normalizeHost(c.in)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if got != c.want {
				t.Errorf("host = %q, want %q", got, c.want)
			}
		})
	}
}
