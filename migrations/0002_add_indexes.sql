-- Index for unfiltered queries sorted by visit_date
CREATE INDEX IF NOT EXISTS idx_visits_date
ON airport_visits (visit_date DESC);

-- Composite covering index for username-filtered queries sorted by visit_date
CREATE INDEX IF NOT EXISTS idx_visits_user_date
ON airport_visits (username, visit_date DESC, iata_code);
