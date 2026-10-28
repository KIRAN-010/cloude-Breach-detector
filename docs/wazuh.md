# Wazuh integration

1. Install a supported, matching manager/indexer/dashboard stack using the vendor guide. Keep ports on trusted networks, use verified TLS, and configure the supported identity path with MFA. Separate viewer, analyst and administrator roles. Do not expose a default install publicly.
2. Back up `/var/ossec/etc/ossec.conf` and custom rules. Merge `wazuh/aws-s3.xml.example` within `ossec_config`, replace the bucket/date, and configure `cloude-breach-collector` using `wazuh/aws-config.example`. On EC2, source credentials come from the host role. For a local host, use a supported temporary-credential provider; verify unattended refresh. Never paste long-lived keys into XML.
3. Install `detections/cloudtrail_candidates.xml` and `detections/replay_rules.xml` under `/var/ossec/etc/rules/` with restrictive permissions. Check ID collisions with your existing rules. Run `/var/ossec/bin/wazuh-analysisd -t` before restarting the manager. Restore the backup if validation fails.
4. Use `/var/ossec/bin/wazuh-logtest` to submit one JSON record at a time. For raw fixtures, the collector envelope is `{"integration":"aws","aws":{...CloudTrail event...}}`; inspect an actual collector event before assuming identical field mapping. Record the decoder, actual rule ID and level. Test all positive and negative fixtures on the deployed version.
5. For optional semantic replay, generate `replay.jsonl` locally and use `wazuh/replay-input.xml` to ingest from `/var/log/cloude-breach/replay.jsonl`. Only the service account may write this file. Append only new records to a production localfile feed; the replay CLI regenerates a complete snapshot and must not be used as an unattended incremental feed. Use a fresh demo log/manager test session to avoid confusing duplicate ingestion.
6. Confirm the manager log records successful S3 collection and the indexer has current alerts. Observe permissions errors and oldest pending objects. The included replay health file is **not** live collector health monitoring.
7. Import `dashboards/lab-search.ndjson` through Dashboards saved objects. Map the `wazuh-alerts-*` index pattern if prompted. The saved search is a starting view, not the complete required operations dashboard. Set the time zone explicitly to UTC and select the fixture event date when replaying old events.

Required live verification: source object lineage, ingestion restart, permission denial/recovery, native rule outcomes, dashboard role boundaries, 14-day searchable retention and known benign canary freshness. A screenshot must be captured from this actual installation after verification.

References:
- https://documentation.wazuh.com/current/cloud-security/amazon/services/supported-services/cloudtrail.html
- https://documentation.wazuh.com/current/cloud-security/amazon/services/prerequisites/credentials.html
- https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html
