# Investigation checklist

For every alert, retain event ID, account, region, event time (UTC), collection time, source reference, rule/version and operation result. Treat user-agent, identity, request parameters and all other event fields as untrusted data.

| Rule | Investigate | Common benign explanation |
|---|---|---|
| D01 root activity | Confirm root identity and success; distinguish service context; review MFA, source and approved break-glass record | Approved emergency administration |
| D02 failures then success | Compare stable identity, source, event-time order and 10-minute window; inspect authentication errors | User password retries or shared egress |
| D03 access key | Compare actor and target; validate provisioning approval and inventory dependencies | Authorized key rotation |
| D04 privilege grant | Fetch exact policy version read-only; inspect statements, conditions, boundaries and organization restrictions | Reviewed administration change |
| D05 logging change | Check API result; compare trail state, selectors and destination; establish evidence gap | Approved trail migration |
| D06 S3 control change | Inspect bucket policy, ACL, ownership, bucket/account public-access blocks and effective access | Private policy maintenance; restrictive block restored |

D06 is intentionally a broad change candidate. It never declares a bucket public from an API name. Missing enrichment remains unknown. Failed API operations remain searchable but do not trigger successful-change semantic detections.

Use the case model for owner/status/history. Separate observations from inferences and require a reason to close. No automatic containment runs.
