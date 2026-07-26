package backend

import (
	"context"
	"errors"
	"fmt"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

var errTemplateValidatorUnavailable = errors.New("no healthy template validator is available")

// validateCustomTemplate selects the first registered node, ordered by name,
// that the health monitor has positively observed as healthy. It may try another
// healthy node after a transport failure, but never persists based on an unknown
// or unhealthy node.
func (s *Server) validateCustomTemplate(ctx context.Context, yaml []byte) (types.TemplateValidationResult, error) {
	var result types.TemplateValidationResult
	err := s.withHealthyTemplateValidator(ctx, func(client *ScannerClient) error {
		var err error
		result, err = client.ValidateTemplate(ctx, yaml)
		if err == nil && result.NucleiVersion == "" {
			err = errors.New("scanner returned no nuclei version")
		}
		return err
	})
	return result, err
}

// validateCustomTemplateBatch builds one transient bundle from the exact
// create/overwrite/rename writes selected by the import policy. Healthy-node
// failover reuses the immutable bytes and never activates the bundle.
func (s *Server) validateCustomTemplateBatch(
	ctx context.Context,
	writes []store.TemplateImportWrite,
) (types.TemplateBatchValidationResult, error) {
	bodies := make([]store.Template, len(writes))
	for i := range writes {
		bodies[i] = writes[i].Template
	}
	bundle, _, err := buildCatalogBundle(bodies)
	if err != nil {
		return types.TemplateBatchValidationResult{}, fmt.Errorf("build template validation bundle: %w", err)
	}
	var result types.TemplateBatchValidationResult
	err = s.withHealthyTemplateValidator(ctx, func(client *ScannerClient) error {
		var err error
		result, err = client.ValidateTemplateBatch(ctx, bundle)
		if err == nil && result.NucleiVersion == "" {
			err = errors.New("scanner returned no nuclei version")
		}
		return err
	})
	return result, err
}

func (s *Server) withHealthyTemplateValidator(
	ctx context.Context,
	validate func(*ScannerClient) error,
) error {
	if s.store == nil || s.orch == nil || s.orch.Health() == nil {
		return errTemplateValidatorUnavailable
	}
	nodes, err := s.store.ListScannerNodes(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%w: %v", errTemplateValidatorUnavailable, ctx.Err())
		}
		return fmt.Errorf("list template validation nodes: %w", err)
	}

	var lastErr error
	for _, node := range nodes {
		health, known := s.orch.Health().Get(node.ID)
		if !known || !health.Healthy {
			continue
		}
		client, err := clientForNode(node)
		if err == nil {
			err = validate(client)
			if err == nil {
				return nil
			}
		}
		lastErr = fmt.Errorf("node %q: %w", node.Name, err)
		if s.log != nil {
			s.log.Warn("template validation node failed", "node", node.Name, "err", err)
		}
	}
	if lastErr != nil {
		return fmt.Errorf("%w: %v", errTemplateValidatorUnavailable, lastErr)
	}
	return errTemplateValidatorUnavailable
}
