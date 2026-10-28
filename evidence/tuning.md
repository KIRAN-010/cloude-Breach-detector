# False-positive tuning example

Initial hypothesis: every CreateAccessKey is suspicious. In the labeled set this would flag `D03-approved`, an explicitly approved same-user provisioning path.

Implemented behavior: same-user creation with operator-supplied `approved_provisioning=true` is not a D03 match; cross-user creation still is. This reduces one known benign fixture alert while retaining `D03-positive`. The flag must come from trusted approval context, never from an untrusted CloudTrail field. Live approval enrichment and expiring suppressions are not implemented; default is unapproved.

D06 remains intentionally broad. Reducing D06 noise requires effective-state enrichment and a reviewed workflow, not silently treating absent evidence as safe.
