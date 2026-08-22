# Q3836: checksum/attestation not enforced for binaries - ExtBrowse in browse.go

## Question
Does `ExtBrowse` in [pkg/cmd/extension/browse/browse.go](pkg/cmd/extension/browse/browse.go#L380) install a downloaded extension binary without verifying a checksum or attestation bound to the source repository?

## Target
- File/function: [pkg/cmd/extension/browse/browse.go:380](pkg/cmd/extension/browse/browse.go#L380) - `ExtBrowse`
- Entrypoint: gh extension browse
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Serve a different binary than advertised from the release host.
- Invariant to test: Binary installs verify integrity against a signed/attested value.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with a mismatched artifact asserting install failure.
