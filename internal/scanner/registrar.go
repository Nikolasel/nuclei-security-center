package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

// Registrar periodically self-registers this node with the backend's registry
// (#22): a node→backend metadata heartbeat carrying the node's endpoint, zone,
// tags, and capabilities. It is the one call a node makes to the backend; scan
// traffic still flows strictly backend→node. It authenticates with the shared
// scanner token — the same secret the backend uses to reach the node.
type Registrar struct {
	backendURL string
	token      string
	reg        types.NodeRegistration
	version    func() string
	interval   time.Duration
	http       *http.Client
	log        *slog.Logger
}

// RegistrarConfig configures self-registration. All fields except Version come
// from the environment; Version supplies the node's nuclei version at each beat.
type RegistrarConfig struct {
	BackendURL string
	Token      string
	Name       string
	Endpoint   string
	Zone       string
	Tags       []string
	Version    func() string
	Interval   time.Duration
}

// NewRegistrar builds a Registrar, or returns nil if BackendURL/Endpoint are
// unset (self-registration disabled — the single-node/static-config path).
func NewRegistrar(cfg RegistrarConfig, log *slog.Logger) *Registrar {
	if cfg.BackendURL == "" || cfg.Endpoint == "" {
		return nil
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Registrar{
		backendURL: strings.TrimRight(cfg.BackendURL, "/"),
		token:      cfg.Token,
		reg: types.NodeRegistration{
			Name:     cfg.Name,
			Endpoint: cfg.Endpoint,
			Zone:     cfg.Zone,
			Tags:     cfg.Tags,
		},
		version:  cfg.Version,
		interval: interval,
		http:     &http.Client{Timeout: 10 * time.Second},
		log:      log,
	}
}

// Start registers immediately, then heartbeats on the interval until ctx ends.
func (r *Registrar) Start(ctx context.Context) {
	go func() {
		r.register(ctx)
		t := time.NewTicker(r.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r.register(ctx)
			}
		}
	}()
}

func (r *Registrar) register(ctx context.Context) {
	reg := r.reg
	if r.version != nil {
		reg.NucleiVersion = r.version()
	}
	body, err := json.Marshal(reg)
	if err != nil {
		r.log.Warn("registrar: marshal", "err", err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.backendURL+"/api/nodes/register", bytes.NewReader(body))
	if err != nil {
		r.log.Warn("registrar: build request", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.token)
	resp, err := r.http.Do(req)
	if err != nil {
		// A backend blip must not crash the node; it re-tries next interval.
		r.log.Warn("registrar: heartbeat failed", "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		r.log.Warn("registrar: unexpected status", "status", resp.StatusCode)
	}
}
