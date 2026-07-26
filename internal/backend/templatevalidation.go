package backend

import (
	"context"
	"errors"
	"fmt"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

var errTemplateValidatorUnavailable = errors.New("no healthy template validator is available")

// validateCustomTemplate selects the first registered node, ordered by name,
// that the health monitor has positively observed as healthy. It may try another
// healthy node after a transport failure, but never persists based on an unknown
// or unhealthy node.
func (s *Server) validateCustomTemplate(ctx context.Context, yaml []byte) (types.TemplateValidationResult, error) {
	if s.store == nil || s.orch == nil || s.orch.Health() == nil {
		return types.TemplateValidationResult{}, errTemplateValidatorUnavailable
	}
	nodes, err := s.store.ListScannerNodes(ctx)
	if err != nil {
		return types.TemplateValidationResult{}, fmt.Errorf("list template validation nodes: %w", err)
	}

	var lastErr error
	for _, node := range nodes {
		health, known := s.orch.Health().Get(node.ID)
		if !known || !health.Healthy {
			continue
		}
		client, err := clientForNode(node)
		if err == nil {
			var result types.TemplateValidationResult
			result, err = client.ValidateTemplate(ctx, yaml)
			if err == nil && result.NucleiVersion == "" {
				err = errors.New("scanner returned no nuclei version")
			}
			if err == nil {
				return result, nil
			}
		}
		lastErr = fmt.Errorf("node %q: %w", node.Name, err)
		if s.log != nil {
			s.log.Warn("template validation node failed", "node", node.Name, "err", err)
		}
	}
	if lastErr != nil {
		return types.TemplateValidationResult{}, fmt.Errorf("%w: %v", errTemplateValidatorUnavailable, lastErr)
	}
	return types.TemplateValidationResult{}, errTemplateValidatorUnavailable
}
