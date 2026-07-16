-- Schedules had no way to override the fixed 600s scan timeout (defaultOptions
-- in internal/backend/http.go) the way the ad-hoc POST /api/scans path now can.
-- NULL means "use the default", mirroring how the ad-hoc path's optional
-- timeout_sec override works.
ALTER TABLE schedules ADD COLUMN IF NOT EXISTS timeout_sec INTEGER;
