# Deploy into an isolated lab account

## Prerequisites

Python 3.11+, Git, Terraform 1.10.5 (or compatible <2), AWS CLI v2, short-lived AWS credentials, and an existing Wazuh installation. Start with 4-8 CPU cores, 8-16 GB RAM and 50-100 GB SSD; this is a planning estimate, not a measured sizing result. Use the official Wazuh installation guide and keep manager/indexer/dashboard on one vendor-supported matching release. Record exact versions in the acceptance evidence; this repository does not claim a tested Wazuh version.

The Terraform AWS provider is pinned to 6.42.0. Generate and review `.terraform.lock.hcl` on the first successful init and commit it. Provider retrieval and Terraform execution were unavailable in the authoring environment; CI performs init/validate.

## State bootstrap

Use an existing, separate, private S3 state bucket with encryption, versioning, TLS-only access, and restricted IAM. Terraform's S3 backend uses `use_lockfile=true`; allow the deployment identity access to the exact state object and lock object, including lock-object deletion. Keep a separate key for each environment. Never use the CloudTrail archive itself as state storage. Bootstrap must be performed by the account administrator; the configuration intentionally does not pretend it can create its own backend before init.

## Plan and apply

1. Authenticate using AWS IAM Identity Center/SSO or another short-lived identity. Verify `aws sts get-caller-identity` is the intended isolated account.
2. Copy `infra/backend.hcl.example` to a local `backend.hcl`, and `infra/terraform.tfvars.example` to `infra/terraform.tfvars`. Set state bucket, owner, expiry, budget email, exact existing collector host role ARN and external ID. The host role also needs permission to assume the collector role.
3. Run:

```bash
terraform -chdir=infra init -backend-config=../backend.hcl
terraform -chdir=infra fmt
terraform -chdir=infra validate
terraform -chdir=infra plan -out=lab.tfplan
# Review the account, selected data buckets, trust and expected cost before applying.
terraform -chdir=infra apply lab.tfplan
terraform -chdir=infra output -json coverage_manifest > output/coverage-manifest.json
```

Create `output/` before the final command. Keep plans, state, coverage account identifiers and real logs out of the public repository. The budget covers account spend, not just project tags.

4. Configure [Wazuh](wazuh.md). Confirm actual log delivery, collector read permission and alert indexing using a benign authorized action first.
5. Run the live acceptance checks in [release-gates](release-gates.md); record actual results, deployed versions, limitations and cost. Do not declare release complete from Terraform validation alone.

## Integrity

Digest generation is enabled. It does not validate files. Set `TRAIL_ARN`, `START_TIME` and `END_TIME`, then run `bash scripts/validate_integrity.sh` from an identity with appropriate read access. Inspect invalid files, missing digests and delivery gaps. Schedule daily validation on the operator host and run it before exporting incident evidence. Scheduling and the first successful cloud validation remain operator tasks.
