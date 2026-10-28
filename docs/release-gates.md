# Requirement traceability and release gates

The supplied PDF is the target specification. v0.1.0 is a working offline foundation, **not completion of every P0 or P1 acceptance gate**.

| Requirement group | Delivered | Gate still open |
|---|---|---|
| INF-01..06 | Terraform archive/trail/collector/budget, state configuration and teardown guide | Backend bootstrap, lockfile, clean plan/apply and second deployment |
| ING-01..06 | Replay normalization, durable dedup, references, late flag; native S3 config; data selectors | Live collection, streaming lateness/retries/checkpointing, actual integrity validation |
| D01..06 | Six semantic replay rules with positive/negative scenarios; native candidate/context XML | Native Wazuh logtest equivalence, policy version lookup and effective exposure verification |
| D07..12 | Catalog backlog and exact scope | Implementation and fixtures |
| DET-01..06 | Versioned catalog, threshold notes, evaluation and limitations | Live observation, expiry-bound suppressions, approval/review lifecycle |
| UI-01..02 | Saved search export and investigation guide | Full operational views, trend/noise/health panels and actual screenshot |
| CASE-01..03 | Case fields, history-preserving workflow, report template, synthetic examples | Live case/export access controls and redaction verification |
| CASE-04 | Stable deterministic alert IDs | Notification delivery/dedup/retry adapter (optional) |
| RES-01..05 | Recommendation-only dry run and scope tests | Approval worker, stale approvals, pre-state/readback, idempotency and rollback |
| SEC-01..06 | No custom API, least-privilege infrastructure intent, threat model, no embedded secrets | Live MFA/RBAC/TLS tests, supply-chain scanning/SBOM, retention verification |
| NFR-01..06 | Local health counters, persistent replay restart test and operations guide | Live freshness canary, 10,000-event/10-minute benchmark, index rebuild and measured RTO |
| T01..05 | Offline unit/schema/detection/security/restart tests and labeled evaluation | Real cloud-to-index integration, failure injection and live security tests |

## Acceptance sequence

1. CI passes; review Terraform plan and policy boundaries.
2. Deploy clean lab; record exact tool/service versions and coverage manifest.
3. Confirm real CloudTrail object delivery and trace a benign event through Wazuh.
4. Run all six positive/negative scenarios through native logtest and live ingestion; retain actual outputs.
5. Verify viewer/analyst/admin boundaries and protected raw access; collect a redacted real screenshot.
6. Demonstrate two investigations, a recommendation-only response, collector restart and index rebuild.
7. Publish measured latency and cost only after the declared benchmark. Current performance targets are not achievements.
8. Close all P0 gaps before promoting from foundation to P0 release. P1 requires twelve detections and response approval tests.
