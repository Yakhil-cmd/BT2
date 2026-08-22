# Q2389: checksum/attestation not enforced for binaries - (Extension).Owner in extension.go

## Question
Does `Owner` in [pkg/cmd/extension/extension.go](pkg/cmd/extension/extension.go#L182) install a downloaded extension binary without verifying a checksum or attestation bound to the source repository?

## Target
- File/function: [pkg/cmd/extension/extension.go:182](pkg/cmd/extension/extension.go#L182) - `(Extension).Owner`
- Entrypoint: gh extension extension
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Serve a different binary than advertised from the release host.
- Invariant to test: Binary installs verify integrity against a signed/attested value.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with a mismatched artifact asserting install failure.
