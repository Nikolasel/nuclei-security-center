package backend

import (
	"net/http"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// Global app settings API (#95, #336). Admin-only: the settings surface is
// infrastructure configuration (scan-retention policy plus a read-only view of
// the process environment), so both read and write require admin — consistent
// with scanner-node/service-account management.

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.store.GetAppSettings(r.Context())
	if err != nil {
		s.serverError(w, "get app settings", err)
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) handleGetEnvironment(w http.ResponseWriter, r *http.Request) {
	resp := EnvConfigResponse{Variables: resolveEnvConfig()}
	// Seed-only template-sync source (#343): after the one-time startup seed the
	// DB wins, so the effective value is what app_settings holds. The
	// repository is shown sanitized — credentials never leave the backend.
	if s.store != nil {
		src, err := s.store.GetTemplateSyncSource(r.Context())
		if err != nil {
			s.serverError(w, "read template sync source", err)
			return
		}
		if src.Repo != "" || src.Ref != "" {
			for i := range resp.Variables {
				switch resp.Variables[i].Name {
				case "TEMPLATE_SYNC_REPO":
					if src.Repo == "" {
						resp.Variables[i].Effective = strPtr("")
					} else {
						resp.Variables[i].Effective = strPtr(SafeTemplateRepo(src.Repo))
					}
				case "TEMPLATE_SYNC_REF":
					if src.Ref != "" {
						resp.Variables[i].Effective = strPtr(src.Ref)
					}
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// updateSettingsRequest is the PUT /api/settings body. RetentionDays is a pointer
// so an explicit null (clear the window) is distinguishable from omitted. When
// retention is enabled the window must be a positive integer. RetentionIncludeAdhoc
// opts ad-hoc (target-less) scans into the sweep.
type updateSettingsRequest struct {
	RetentionEnabled      bool `json:"retention_enabled"`
	ScanRetentionDays     *int `json:"scan_retention_days"`
	RetentionIncludeAdhoc bool `json:"retention_include_adhoc"`
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req updateSettingsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.ScanRetentionDays != nil && (*req.ScanRetentionDays <= 0 || *req.ScanRetentionDays > store.MaxScanRetentionDays) {
		http.Error(w, "scan_retention_days must be between 1 and 36500 (or null to unset)", http.StatusBadRequest)
		return
	}
	if req.RetentionEnabled && (req.ScanRetentionDays == nil || *req.ScanRetentionDays <= 0 || *req.ScanRetentionDays > store.MaxScanRetentionDays) {
		http.Error(w, "scan_retention_days must be between 1 and 36500 when retention is enabled", http.StatusBadRequest)
		return
	}

	updated, err := s.store.UpdateAppSettings(r.Context(), store.AppSettings{
		RetentionEnabled:      req.RetentionEnabled,
		ScanRetentionDays:     req.ScanRetentionDays,
		RetentionIncludeAdhoc: req.RetentionIncludeAdhoc,
	}, actorFrom(r))
	if err != nil {
		s.serverError(w, "update app settings", err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}
