# Q3967: enterprise/dotcom misclassification - newEnforcementCriteria in policy.go

## Question
Can an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims make `newEnforcementCriteria` in [pkg/cmd/attestation/verify/policy.go](pkg/cmd/attestation/verify/policy.go#L30) misclassify a host as enterprise or dotcom, selecting different API base paths, auth rules, or feature gates than the user intends?

## Target
- File/function: [pkg/cmd/attestation/verify/policy.go:30](pkg/cmd/attestation/verify/policy.go#L30) - `newEnforcementCriteria`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish a remote whose host triggers the wrong branch and observe the relaxed path.
- Invariant to test: Classification derives from the exact configured host with no remote input.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting classification for lookalike and mixed-case hosts.
