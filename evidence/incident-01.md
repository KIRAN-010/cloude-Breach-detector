# SIMULATION: root sign-in

Case: SYN-001. Severity: high. Status: exercise reviewed. Scope: invented account 111122223333.

Observation: `D01-positive-0` at 2026-10-28 10:00 UTC reports a successful ConsoleLogin from a Root identity. Source: `fixtures/scenarios.json`, scenario `D01-positive`. Semantic replay produces D01; see evaluation.json.

Inference: this warrants review but does not establish compromise. Approved break-glass access is a benign alternative. No real MFA, credential provenance or account ownership evidence exists because this is synthetic.

Containment: recommendation only; no cloud action occurred. Recovery: no real resource was changed. Closure: synthetic exercise, not a confirmed incident. Follow-up: repeat in an authorized isolated account, verify native Wazuh behavior and retain real source/digest references.
