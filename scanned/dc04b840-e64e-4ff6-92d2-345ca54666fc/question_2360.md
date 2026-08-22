# Q2360: checksum/attestation not enforced for binaries - (Manager).Dispatch in manager.go

## Question
Does `Dispatch` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L92) install a downloaded extension binary without verifying a checksum or attestation bound to the source repository?

## Target
- File/function: [pkg/cmd/extension/manager.go:92](pkg/cmd/extension/manager.go#L92) - `(Manager).Dispatch`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Serve a different binary than advertised from the release host.
- Invariant to test: Binary installs verify integrity against a signed/attested value.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with a mismatched artifact asserting install failure.
