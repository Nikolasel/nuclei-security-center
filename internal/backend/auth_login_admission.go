package backend

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate" // canonical token bucket; avoid hand-rolled refill logic
)

const (
	// These defaults are intentionally conservative; deployments can tune them
	// through the AUTH_LOGIN_* environment variables within the hard bounds below.
	DefaultAuthLoginRate          = 1.0
	DefaultAuthLoginBurst         = 5
	DefaultAuthLoginMaxClients    = 4096
	MaxConfiguredAuthLoginRate    = 1000.0
	MaxConfiguredAuthLoginBurst   = 1000
	MaxConfiguredAuthLoginClients = 65_536
	// MaxTrustedProxyCIDRs bounds trusted proxy configuration at startup.
	MaxTrustedProxyCIDRs = 64
	maxForwardedForBytes = 4096
	maxForwardedForHops  = 32

	// authLoginRate and authLoginBurst allow a legitimate browser a short burst
	// of retries while sharply limiting anonymous flow creation over time.
	authLoginRate       rate.Limit = DefaultAuthLoginRate
	authLoginBurst                 = DefaultAuthLoginBurst
	authLoginMaxClients            = DefaultAuthLoginMaxClients
	// return_to is only a relative browser path. Keep the stored value small even
	// before the callback applies the open-redirect validation.
	maxAuthReturnToBytes = 2048
)

type loginAdmission struct {
	mu         sync.Mutex
	clients    map[string]*loginClient
	limit      rate.Limit
	burst      int
	maxClients int
	now        func() time.Time
}

type loginClient struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// trustedProxySet contains only prefixes normalized by newTrustedProxySet.
// Keeping the normalized form private prevents request-time callers from
// accidentally passing raw IPv4-mapped prefixes to Prefix.Contains.
type trustedProxySet []netip.Prefix

type loginAdmissionConfig struct {
	limit      rate.Limit
	burst      int
	maxClients int
}

func newLoginAdmission() *loginAdmission {
	return newLoginAdmissionWithConfig(loginAdmissionConfig{
		limit:      authLoginRate,
		burst:      authLoginBurst,
		maxClients: authLoginMaxClients,
	})
}

func newLoginAdmissionWithConfig(cfg loginAdmissionConfig) *loginAdmission {
	return &loginAdmission{
		clients:    make(map[string]*loginClient),
		limit:      cfg.limit,
		burst:      cfg.burst,
		maxClients: cfg.maxClients,
		now:        time.Now,
	}
}

func (a *loginAdmission) allow(clientKey string) bool {
	clientKey = strings.TrimSpace(clientKey)
	if clientKey == "" {
		clientKey = "unknown"
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()

	client, ok := a.clients[clientKey]
	if !ok {
		if a.maxClients <= 0 {
			return false
		}
		for len(a.clients) >= a.maxClients {
			a.evictStalestLocked()
		}
		client = &loginClient{limiter: rate.NewLimiter(a.limit, a.burst)}
		a.clients[clientKey] = client
	}
	client.lastSeen = now
	return client.limiter.AllowN(now, 1)
}

func (a *loginAdmission) evictStalestLocked() {
	var staleKey string
	var staleAt time.Time
	found := false
	for key, client := range a.clients {
		if !found || client.lastSeen.Before(staleAt) {
			staleKey = key
			staleAt = client.lastSeen
			found = true
		}
	}
	if found {
		delete(a.clients, staleKey)
	}
}

// loginAdmitter lazily initializes the limiter so tests and other internal
// construction paths cannot accidentally bypass admission by omitting a field.
func (a *Authenticator) loginAdmitter() *loginAdmission {
	a.loginAdmissionOnce.Do(func() {
		a.loginAdmission = newLoginAdmissionWithConfig(loginAdmissionConfigFromAuth(a.cfg))
	})
	return a.loginAdmission
}

func loginAdmissionConfigFromAuth(cfg AuthConfig) loginAdmissionConfig {
	admission := loginAdmissionConfig{
		limit:      authLoginRate,
		burst:      authLoginBurst,
		maxClients: authLoginMaxClients,
	}
	if cfg.LoginRate != 0 {
		admission.limit = rate.Limit(cfg.LoginRate)
	}
	if cfg.LoginBurst != 0 {
		admission.burst = cfg.LoginBurst
	}
	if cfg.LoginMaxClients != 0 {
		admission.maxClients = cfg.LoginMaxClients
	}
	return admission
}

func validateLoginAdmissionConfig(cfg AuthConfig) error {
	if math.IsNaN(cfg.LoginRate) || math.IsInf(cfg.LoginRate, 0) || cfg.LoginRate < 0 || cfg.LoginRate > MaxConfiguredAuthLoginRate {
		return fmt.Errorf("LoginRate must be between 0 and %g", MaxConfiguredAuthLoginRate)
	}
	if cfg.LoginBurst < 0 || cfg.LoginBurst > MaxConfiguredAuthLoginBurst {
		return fmt.Errorf("LoginBurst must be between 0 and %d", MaxConfiguredAuthLoginBurst)
	}
	if cfg.LoginMaxClients < 0 || cfg.LoginMaxClients > MaxConfiguredAuthLoginClients {
		return fmt.Errorf("LoginMaxClients must be between 0 and %d", MaxConfiguredAuthLoginClients)
	}
	if len(cfg.TrustedProxyCIDRs) > MaxTrustedProxyCIDRs {
		return fmt.Errorf("TrustedProxyCIDRs must contain at most %d prefixes", MaxTrustedProxyCIDRs)
	}
	for _, prefix := range cfg.TrustedProxyCIDRs {
		if !prefix.IsValid() {
			return fmt.Errorf("TrustedProxyCIDRs contains an invalid prefix")
		}
	}
	return nil
}

// authLoginClientKey uses the TCP peer address only. Forwarded headers are
// deployment-specific and attacker-controlled by default. When the direct peer
// belongs to a configured trusted proxy network, it walks X-Forwarded-For from
// the nearest hop outward and uses the first untrusted address. A proxy must
// strip or overwrite client-supplied forwarding headers before this boundary.
func authLoginClientKey(r *http.Request, trustedProxyCIDRs trustedProxySet) string {
	remote := strings.TrimSpace(r.RemoteAddr)
	peer, ok := parseRemoteAddr(remote)
	if !ok {
		return remoteAddrKey(remote)
	}
	if !containsTrustedProxy(peer, trustedProxyCIDRs) {
		return peer.String()
	}
	if client, ok := forwardedClientIP(strings.Join(r.Header.Values("X-Forwarded-For"), ","), trustedProxyCIDRs); ok {
		return client.String()
	}
	return peer.String()
}

func parseRemoteAddr(remote string) (netip.Addr, bool) {
	if host, _, err := net.SplitHostPort(remote); err == nil && host != "" {
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return netip.Addr{}, false
		}
		return addr.Unmap(), true
	}
	addr, err := netip.ParseAddr(remote)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func remoteAddrKey(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil && host != "" {
		return host
	}
	if remote == "" {
		return "unknown"
	}
	return remote
}

func containsTrustedProxy(addr netip.Addr, prefixes trustedProxySet) bool {
	addr = addr.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func forwardedClientIP(header string, trustedProxyCIDRs trustedProxySet) (netip.Addr, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return netip.Addr{}, false
	}
	if len(header) > maxForwardedForBytes {
		header = header[len(header)-maxForwardedForBytes:]
	}
	remaining := header
	for hop := 0; hop < maxForwardedForHops && remaining != ""; hop++ {
		comma := strings.LastIndexByte(remaining, ',')
		token := remaining
		if comma >= 0 {
			token = remaining[comma+1:]
		}
		if addr, err := netip.ParseAddr(strings.TrimSpace(token)); err == nil {
			addr = addr.Unmap()
			if !containsTrustedProxy(addr, trustedProxyCIDRs) {
				return addr, true
			}
		}
		if comma < 0 {
			break
		}
		remaining = remaining[:comma]
	}
	return netip.Addr{}, false
}

func newTrustedProxySet(prefixes []netip.Prefix) trustedProxySet {
	if len(prefixes) == 0 {
		return nil
	}
	normalized := make(trustedProxySet, len(prefixes))
	for index, prefix := range prefixes {
		normalized[index] = normalizeTrustedProxyPrefix(prefix)
	}
	return normalized
}

func normalizeTrustedProxyPrefix(prefix netip.Prefix) netip.Prefix {
	prefix = prefix.Masked()
	addr := prefix.Addr()
	if addr.Is4In6() && prefix.Bits() >= 96 {
		return netip.PrefixFrom(addr.Unmap(), prefix.Bits()-96).Masked()
	}
	return prefix
}

// authReturnTo keeps only the same safe relative-path contract enforced at the
// callback, and rejects oversized values rather than truncating them into a
// potentially different path.
func authReturnTo(value string) string {
	if len(value) > maxAuthReturnToBytes {
		return ""
	}
	return safeReturnTo(value)
}
