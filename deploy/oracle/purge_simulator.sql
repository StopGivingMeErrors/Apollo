-- Remove demo/simulator history so the dashboard shows sensor traffic only.
DELETE FROM events WHERE source = 'simulator';
DELETE FROM alerts WHERE source = 'simulator';
DELETE FROM alerts WHERE source = 'mixed';
DELETE FROM campaigns;
DELETE FROM ip_counts;
VACUUM;
