# Q0396: git output parsed as trusted - extractAttestationDetail in verify.go

## Question
Does `extractAttestationDetail` in [pkg/cmd/attestation/verify/verify.go](pkg/cmd/attestation/verify/verify.go#L351) parse git stdout that a hostile repository can shape (branch names, remote lists, config values) and use it for a host or path decision?

## Target
- File/function: [pkg/cmd/attestation/verify/verify.go:351](pkg/cmd/attestation/verify/verify.go#L351) - `extractAttestationDetail`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish a repo whose branch names embed delimiters used by gh's parser.
- Invariant to test: Git output is parsed with NUL-delimited/porcelain formats and validated.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with delimiter-bearing names asserting correct parsing.
