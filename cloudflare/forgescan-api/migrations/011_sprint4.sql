-- ─────────────────────────────────────────────────────────────────────────────
-- Sprint 4: New RedOps Agents + Cross-Product Correlation
-- ─────────────────────────────────────────────────────────────────────────────

-- New network-category agent types
INSERT OR IGNORE INTO redops_agent_types (id, category, display_name, description, test_count, mitre_techniques, owasp_categories, enabled)
VALUES
  ('net_segmentation', 'network', 'Network Segmentation', 'Tests network segmentation, VLAN isolation, firewall rules, and lateral movement boundaries', 24, '["T1046","T1021","T1048","T1572","T1090"]', '["A05:2021"]', 1),
  ('net_ssl_tls',      'network', 'SSL/TLS Configuration', 'Audits SSL/TLS certificate validity, cipher suites, protocol versions, and HSTS enforcement', 30, '["T1557","T1040","T1056.003"]', '["A02:2021","A07:2021"]', 1),
  ('net_dns_security', 'network', 'DNS Security',          'Tests DNSSEC validation, zone transfer protections, DNS rebinding, cache poisoning vectors, and subdomain takeover', 22, '["T1071.004","T1568","T1584.001"]', '["A05:2021","A08:2021"]', 1);

-- Cross-product correlation index
CREATE INDEX IF NOT EXISTS idx_redops_findings_cve ON redops_findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_redops_findings_cwe ON redops_findings(cwe_id);
CREATE INDEX IF NOT EXISTS idx_findings_vendor_id  ON findings(vendor_id);

-- Event subscriptions for campaign-complete -> SOC alert
INSERT OR IGNORE INTO event_subscriptions (id, name, event_pattern, handler_type, handler_config, conditions, is_active, priority, created_at, updated_at)
VALUES
  ('sub-campaign-soc', 'RedOps Campaign Complete → SOC Summary Alert', 'forge.redops.campaign.completed', 'custom', '{"target":"forgesoc"}', NULL, 1, 5, datetime('now'), datetime('now'));
