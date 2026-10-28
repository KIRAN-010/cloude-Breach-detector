# Cloude Breach Detection

An AWS CloudTrail + Wazuh security engineering lab for detecting suspicious identity, permissions, logging and S3 access-control activity. Built from the supplied **Cloud Breach Detection Lab Requirements v1.0**.

**Status: v0.1.0 offline-tested implementation. Live AWS deployment and Wazuh acceptance are pending. This is not a production-certified system.**

## Run the local demo

Python 3.11+ is sufficient; the replay tool has no runtime third-party dependencies or AWS credentials.

```bash
git clone https://github.com/KIRAN-010/cloude-Breach-detector.git
cd cloude-Breach-detector
export PYTHONPATH="$PWD/src"
python3 -m unittest discover -s tests -v
python3 scripts/evaluate.py
python3 -m breach_detector.cli fixtures/demo.json --received-at 2026-10-28T10:10:00Z
python3 scripts/demo_case.py
```

Read `replay.jsonl` for normalized evidence and rule matches, `replay.health.json` for processing counters, and `output/demo-case.json` for an auditable case with a response recommendation. Repeating the replay with the same database produces no duplicate input records; durable results regenerate the output file. The fixed collection timestamp is for these synthetic fixtures only.

## Included

| Component | Implementation |
|---|---|
| AWS infrastructure | Multi-region management trail, optional selected S3 data events, TLS-only encrypted/versioned archive, read-only collector role, monthly budget notification |
| D01-D06 | Python semantic replay with labeled positive/negative fixtures; native Wazuh context rules and separate raw-CloudTrail candidate rules |
| Evidence | Stable event/alert identifiers, source references, collection timestamp, failure outcome and missing-context fields |
| Reliability | SQLite atomic input/result persistence, deduplication across restart, malformed-input reporting, late-event flag |
| Analyst workflow | Structured cases, audited transitions, saved-search export, investigation playbooks |
| Controlled response | Scope-checked recommendation-only dry run; no cloud mutation code |
| Validation | Unit/security/recovery checks, evaluation report and GitHub Actions |

## Deploy the lab

Follow [deployment](docs/deployment.md), then [Wazuh integration](docs/wazuh.md). Use one isolated AWS account and a trusted-network Wazuh installation. The initial region is `ap-south-1`; inputs are configurable. Terraform requires an existing protected remote-state bucket and an existing host identity. Never commit credentials or local Terraform state.

Cost drivers include Wazuh compute/storage, CloudTrail data events, S3 storage/requests and transfer. A configurable USD 15 account budget is a notification, **not a spending cap**. No AWS resources have been provisioned by this repository's creation.

## Verified and pending

[Evaluation](evidence/evaluation.json) records actual offline fixture results. [Release gates](docs/release-gates.md) distinguish implemented, locally checked and live-unverified requirements. D07-D12, streaming correlation, policy lookup enrichment, approved response execution, a live dashboard screenshot and the 10,000-event load benchmark remain pending. Six semantic detections passing synthetic fixtures does not prove native Wazuh equivalence or production detection accuracy.

A genuine running Wazuh screenshot must be added after deployment; no simulated dashboard screenshot is presented as evidence.

## Project map

- `infra/`: Terraform and configuration examples
- `src/breach_detector/`: normalization, offline correlation, replay and cases
- `detections/`: native Wazuh XML and versioned catalog
- `fixtures/`, `tests/`, `scripts/`: reproducible evaluation and operator helpers
- `dashboards/`, `playbooks/`: investigation entry points
- `docs/`, `evidence/`: deployment, threat model, operations and measured results

## Teardown

Use [the teardown runbook](docs/operations.md#teardown). Raw logs and object versions are intentionally protected against force deletion; review retention before removing them. Keep remote state until infrastructure cleanup is complete.
