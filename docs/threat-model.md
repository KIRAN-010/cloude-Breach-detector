# Threat model

Assets: raw CloudTrail objects/digests, collector identity, rule configurations, indexed alerts, case evidence and analyst accounts. Actors: authorized operator/analyst, compromised cloud identity, compromised collector, malicious contributor, unauthorized dashboard visitor.

| Abuse case | Control | Validation / remaining gap |
|---|---|---|
| Collector modifies/deletes cloud logs | Collector allows only ListBucket/GetObject | Review Terraform IAM and live deny-write test (pending) |
| Forged or altered evidence | Preserve event/source IDs, digest validation | Local lineage test passed; actual digest validation pending |
| Public archive exposure | Four public-access block controls, TLS-only policy, source-ARN delivery restrictions | Terraform implementation; cloud verification pending |
| Forged enrichment | Restrict replay feed and case files to service/operator accounts | Host permissions must be tested live |
| Credential theft | Short-lived role profile, no embedded credentials, CI pattern check | Full history scanning and release secret scanner remain required |
| Unauthorized response | No mutation implementation; scope/action checks on dry run | Wrong-account rejection test passed |
| Malicious event content | JSON serialization, bounded replay input, no custom HTML renderer | Dashboard field escaping must be checked live |
| Dependency compromise | No runtime Python dependencies; pinned provider/build tools and action commits | SBOM, licenses and image scanning remain release gates |
| Dashboard/raw-data exposure | Vendor RBAC, MFA, TLS and trusted-network access required | Environment-specific configuration and role tests pending |

Logs may contain personal identifiers, source IPs and sensitive request details. Synthetic fixtures use reserved documentation addresses and invented identifiers. Never commit real raw logs, private case notes, access keys, state, backend settings or evidence screenshots containing secrets. Redact exported fields against an allowlist and have an analyst review the result. Automatic general-purpose redaction is not implemented.
