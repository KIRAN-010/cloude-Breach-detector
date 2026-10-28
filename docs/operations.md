# Operations

All cloud exercises require operator-owned lab credentials. No destructive cloud commands are run automatically.

| Symptom | Diagnose | Recover | Verify |
|---|---|---|---|
| No new CloudTrail alerts | Check trail status, recent S3 objects, role session and Wazuh module log | Repair the specific permission/session or collector config | Run a known benign canary and trace its event ID to collection |
| Parse errors | Inspect the errors file and source reference; preserve raw input | Quarantine malformed input, fix producer/normalization and replay | Valid events process; malformed count is visible |
| Expired collector credentials | Check STS identity as Wazuh service user | Restore short-lived provider refresh, never embed keys | New S3 object read succeeds |
| Index unavailable | Check cluster health, manager queue and disk | Restore indexer and replay preserved source with dedup strategy | Event/alert counts and timestamps match expected results |
| Disk full | Check database/index/archive growth | Stop ingestion safely, extend bounded storage or apply approved retention | Resume and check backlog; no silent gaps |
| Noisy D06 alerts | Compare access-control changes to approved maintenance | Tune an explicit workflow/resource after review | Run positive/negative fixtures and record lost coverage |
| Unexpected costs | Inspect budget and billing by service/region | Disable unnecessary data selectors after documenting coverage loss | Confirm lower usage and updated coverage manifest |
| Integrity failure | Review digest intervals, missing files and validation output | Preserve evidence, investigate archive permissions and delivery | Revalidate; never mark missing evidence as verified |

## Backup and recovery

Back up rules, Wazuh configuration, dashboards, cases, SQLite replay state and infrastructure state to encrypted restricted storage. Do not copy credentials into a repository. Use an application-consistent SQLite backup (Python sqlite3 `backup`) or stop the process before copying; copying only a live DB without its WAL can lose data.

The automated `test_persistent_dedup_and_recovery` exercise closes/reopens the SQLite store, retries the same event and checks that exactly one durable result remains. This is a tested local recovery case, not an indexer restore. For the live gate, rebuild a disposable Wazuh index from preserved raw logs, verify sampled source IDs and counts, and record elapsed recovery time. Target: under four hours; unmeasured here.

## Teardown

1. Export and protect evidence/cases, record retention decisions, and stop optional demo replay.
2. Review `terraform -chdir=infra plan -destroy`. Stopping/deleting the trail stops new collection.
3. Archive storage has `force_destroy=false`. Terraform will refuse to remove a non-empty bucket. Preserve it or perform a separately reviewed deletion of all approved objects and versions after retention expires. Do not casually bypass this protection.
4. Run the reviewed destroy when authorized; verify the collector role and budget cleanup. Inspect all regions for independently created lab resources.
5. Keep remote state and backups until cleanup is verified. Remove state objects/versions only through an explicitly approved state-retention procedure. Versioning is recoverability, not immutability.
