# Q1699: checksum/attestation not enforced for binaries - expandAlias in alias.go

## Question
Does `expandAlias` in [pkg/cmd/root/alias.go](pkg/cmd/root/alias.go#L79) install a downloaded extension binary without verifying a checksum or attestation bound to the source repository?

## Target
- File/function: [pkg/cmd/root/alias.go:79](pkg/cmd/root/alias.go#L79) - `expandAlias`
- Entrypoint: gh root alias
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Serve a different binary than advertised from the release host.
- Invariant to test: Binary installs verify integrity against a signed/attested value.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with a mismatched artifact asserting install failure.
