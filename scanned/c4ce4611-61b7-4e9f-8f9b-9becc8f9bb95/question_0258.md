# Q0258: checksum/attestation not enforced for binaries - fetchCommitSHA in http.go

## Question
Does `fetchCommitSHA` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L175) install a downloaded extension binary without verifying a checksum or attestation bound to the source repository?

## Target
- File/function: [pkg/cmd/extension/http.go:175](pkg/cmd/extension/http.go#L175) - `fetchCommitSHA`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Serve a different binary than advertised from the release host.
- Invariant to test: Binary installs verify integrity against a signed/attested value.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with a mismatched artifact asserting install failure.
