# Architecture and decision record ADR-001

Accepted for v0.1.0: use Wazuh as the analyst platform, CloudTrail S3 as raw evidence, and Terraform for AWS configuration. Avoid a second custom SIEM or public API.

The primary live route is CloudTrail -> protected S3 -> supported Wazuh AWS module -> native candidate rules -> indexer -> authenticated Wazuh dashboard. The native rules deliberately say “attempt” or “verify”; they do not claim that an API name establishes a successful breach.

A separate, optional Python **offline replay adapter** normalizes sanitized fixtures, evaluates deeper D01-D06 semantics and emits JSON context consumed by `replay_rules.xml`. This adapter is not automatically attached to the live S3 collector. Its interface is CloudTrail `Records` input -> `integration=cloud_breach_lab` JSONL output, with persistent SQLite input/results and separate errors/health files. Do not treat its context matches as native live coverage. Wazuh typically emits one winning rule per event, whereas replay can record several matches; validate this difference during acceptance.

Trust boundaries: AWS IAM controls log delivery/collection; the Wazuh host and local replay files are trusted processing boundaries; dashboard RBAC controls analyst access; repository write permission controls rules and case files. An attacker who can write the local replay feed can forge context, so restrict it to the integration service account.

Raw S3 keys/event IDs are authoritative evidence references. Replay uses explicit fixture:// references, never fabricated S3 evidence. CloudTrail collection metadata available in live Wazuh must be inspected and mapped before claiming complete per-object lineage. Alerts alone do not preserve every benign raw event. Enable an appropriately protected archives index only after sizing and a 14-day deletion policy are tested.

Tradeoff: standard-library replay is easy to reproduce and has no credential handling. It does not implement a production streaming watermark, live policy retrieval, multi-account collection, or cloud response execution. These are explicit release gates.
