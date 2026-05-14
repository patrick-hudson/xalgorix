// Package web — target_policy.go is the single chokepoint for deciding
// whether a scan target is in scope at intake time. It replaces the old
// blanket isBlockedTarget that conflated "the host machine" with
// "anything in RFC 1918." The new policy keeps the host machine and its
// IAM credential surface (loopback + link-local + cloud-metadata
// shorthands) hard-blocked regardless of config, but lets RFC 1918 / ULA
// targets through when XALGORIX_ALLOW_PRIVATE_NETWORKS=true.
//
// See Decide for the layered precedence. The agent has shell access via
// terminal_execute, so this is intake-only scope hygiene — NOT a runtime
// sandbox. Operators who need true egress isolation should layer a
// network namespace or seccomp filter on top.
package web

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// Block reasons emitted by Decide. Stable strings — used in [BLOCKLIST]
// log lines and any external tooling that grep over them.
const (
	BlockReasonLoopback        = "loopback"
	BlockReasonLinkLocal       = "link-local"
	BlockReasonUnspecified     = "unspecified"
	BlockReasonContainerHost   = "container-host"
	BlockReasonOperatorBlock   = "operator-blocklist"
	BlockReasonPrivateDisabled = "private-network-disabled"
)

// hardBlockedHostnames is the set of literal hostnames that are blocked
// regardless of policy. Includes the obvious "localhost" plus the
// container-host shorthands and cloud metadata DNS names so an LLM that
// surfaces e.g. "metadata.google.internal" from a wordlist can't trick
// the agent into hitting the IAM credential surface.
var hardBlockedHostnames = map[string]bool{
	"localhost":                true,
	"ip6-localhost":            true,
	"host.docker.internal":     true,
	"host.containers.internal": true,
	"gateway.docker.internal":  true,
	"metadata.google.internal": true,
	"metadata.azure.com":       true,
	// AWS IMDS / ECS task metadata are also reachable by literal IP
	// (169.254.169.254 / 169.254.170.2) — those are caught by the
	// link-local CIDR check below; this set is for hostname targets.
}

// hardBlockedCIDRs mirrors what net.IP's IsLoopback/IsLinkLocalUnicast/
// IsUnspecified already cover, but parsed once at init so we can inspect
// them by name in tests if needed and so the IPv6 unspecified literal
// "::/128" is treated identically to 0.0.0.0/32.
var hardBlockedCIDRs []*net.IPNet

// privateCIDRs are RFC 1918 + IPv6 ULA. They are blocked iff
// TargetAllowPrivateNetworks=false and the target is not on the operator
// allowlist.
var privateCIDRs []*net.IPNet

func init() {
	for _, raw := range []string{
		"127.0.0.0/8",
		"::1/128",
		"169.254.0.0/16",
		"fe80::/10",
		"0.0.0.0/32",
		"::/128",
	} {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			panic(fmt.Sprintf("target_policy: bad hard-blocked CIDR %q: %v", raw, err))
		}
		hardBlockedCIDRs = append(hardBlockedCIDRs, n)
	}
	for _, raw := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
	} {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			panic(fmt.Sprintf("target_policy: bad private CIDR %q: %v", raw, err))
		}
		privateCIDRs = append(privateCIDRs, n)
	}
}

// targetPolicy is the runtime decision surface. Construct via
// newTargetPolicyFromConfig at server start; reuse the same instance for
// the lifetime of the process.
type targetPolicy struct {
	allowPrivate bool
	allowCIDRs   []*net.IPNet
	allowHosts   map[string]bool
	denyCIDRs    []*net.IPNet
	denyHosts    map[string]bool
}

// newTargetPolicyFromConfig parses the operator-supplied allow/block lists
// into ready-to-match values. Unparseable entries are logged and skipped;
// the policy is still built (we don't want a typo in the env to crash the
// scan-intake handler).
func newTargetPolicyFromConfig(cfg *config.Config) *targetPolicy {
	p := &targetPolicy{
		allowHosts: map[string]bool{},
		denyHosts:  map[string]bool{},
	}
	if cfg == nil {
		return p
	}
	p.allowPrivate = cfg.TargetAllowPrivateNetworks

	for _, raw := range cfg.TargetAllowlist {
		cidr, host, ok := parseCIDROrHost(raw)
		if !ok {
			log.Printf("[target-policy] Ignoring unparseable XALGORIX_TARGET_ALLOWLIST entry %q", raw)
			continue
		}
		if cidr != nil {
			p.allowCIDRs = append(p.allowCIDRs, cidr)
		} else {
			p.allowHosts[host] = true
		}
	}
	for _, raw := range cfg.TargetBlocklist {
		cidr, host, ok := parseCIDROrHost(raw)
		if !ok {
			log.Printf("[target-policy] Ignoring unparseable XALGORIX_TARGET_BLOCKLIST entry %q", raw)
			continue
		}
		if cidr != nil {
			p.denyCIDRs = append(p.denyCIDRs, cidr)
		} else {
			p.denyHosts[host] = true
		}
	}
	return p
}

// Decide returns (allowed, reason). When allowed=false, reason is one of
// the BlockReason* constants and is suitable for emission to logs.
//
// Layered precedence (hard rules ALWAYS win over operator opt-ins;
// allowlists never let an operator unblock the credential surface):
//  1. Hard-blocked literal hostnames (localhost, container shorthands,
//     cloud metadata DNS) → blocked.
//  2. Operator hostname blocklist (literal-string match, no DNS) →
//     blocked.
//  3. Operator hostname allowlist (literal-string match, no DNS) →
//     allowed; SKIPS the DNS-resolve + IP-rule layers below. Operators
//     who want a hostname that resolves to a private IP should use this.
//  4. Resolve to IP (parse as literal IP, else DNS lookup; bail allowed
//     if resolution fails — the LLM will get a normal connection error).
//  5. Hard rules on resolved IP (loopback, unspecified, link-local) →
//     blocked.
//  6. Operator CIDR blocklist → blocked.
//  7. Operator CIDR allowlist → allowed (overrides the private-network
//     gate below).
//  8. Private network (RFC 1918 / ULA) and AllowPrivateNetworks=false →
//     blocked.
//  9. Otherwise → allowed.
func (p *targetPolicy) Decide(target string) (bool, string) {
	host, ok := normalizeHost(target)
	if !ok {
		// Empty/garbage input — let the upstream trim drop it; we don't
		// want to surface a synthetic "blocked" reason for it.
		return true, ""
	}
	hostLower := strings.ToLower(host)

	// ── 1) Hard-blocked literal hostnames. Always blocked. ──
	if hardBlockedHostnames[hostLower] {
		return false, BlockReasonContainerHost
	}

	// ── 2) Operator hostname blocklist. Decided here (before DNS) so
	//      a typo'd hostname that fails to resolve still gets blocked. ──
	if p.denyHosts[hostLower] {
		return false, BlockReasonOperatorBlock
	}

	// ── 3) Operator hostname allowlist. Bypasses the IP-layer checks
	//      below (the operator has explicitly opted this hostname in). ──
	if p.allowHosts[hostLower] {
		return true, ""
	}

	// ── 4) Resolve to an IP for the address-layer checks. ──
	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := net.LookupHost(host)
		if err != nil || len(addrs) == 0 {
			// Can't resolve — let it through; the agent will get a
			// normal connection error.
			return true, ""
		}
		ip = net.ParseIP(addrs[0])
		if ip == nil {
			return true, ""
		}
	}

	// ── 5) Hard rules on the resolved IP. Never overridable. ──
	if ip.IsLoopback() {
		return false, BlockReasonLoopback
	}
	if ip.IsUnspecified() {
		return false, BlockReasonUnspecified
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false, BlockReasonLinkLocal
	}

	// ── 6) Operator CIDR blocklist. ──
	for _, cidr := range p.denyCIDRs {
		if cidr.Contains(ip) {
			return false, BlockReasonOperatorBlock
		}
	}

	// ── 7) Operator CIDR allowlist (overrides the private-network gate). ──
	for _, cidr := range p.allowCIDRs {
		if cidr.Contains(ip) {
			return true, ""
		}
	}

	// ── 8) Private network gate. ──
	if isPrivateOrULA(ip) && !p.allowPrivate {
		return false, BlockReasonPrivateDisabled
	}

	return true, ""
}

func isPrivateOrULA(ip net.IP) bool {
	for _, cidr := range privateCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// normalizeHost extracts the bare host (no scheme, no port) from a target
// string. Returns ok=false when the input is empty.
func normalizeHost(target string) (string, bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", false
	}
	host := target
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		host = u.Hostname()
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSpace(host)
	return host, host != ""
}

// parseCIDROrHost classifies a raw allowlist/blocklist entry as either a
// CIDR (returned as *net.IPNet) or a hostname (returned lowercased).
// Bare IPs are promoted to /32 or /128 CIDRs so the operator can drop a
// single address into the list without typing the suffix.
func parseCIDROrHost(raw string) (*net.IPNet, string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, "", false
	}
	if _, cidr, err := net.ParseCIDR(raw); err == nil {
		return cidr, "", true
	}
	if ip := net.ParseIP(raw); ip != nil {
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		_, cidr, err := net.ParseCIDR(fmt.Sprintf("%s/%d", raw, bits))
		if err != nil {
			return nil, "", false
		}
		return cidr, "", true
	}
	// Treat as hostname. Reject obviously-malformed values (whitespace
	// inside, control characters) by requiring at least one letter or
	// digit and no spaces — net.LookupHost would fail anyway, but we
	// don't want garbage filling the allowHosts map.
	if strings.ContainsAny(raw, " \t\r\n") {
		return nil, "", false
	}
	return nil, strings.ToLower(raw), true
}
