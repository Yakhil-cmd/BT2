# Q2384: checksum/attestation not enforced for binaries - checkValidExtension in command.go

## Question
Does `checkValidExtension` in [pkg/cmd/extension/command.go](pkg/cmd/extension/command.go#L694) install a downloaded extension binary without verifying a checksum or attestation bound to the source repository?

## Target
- File/function: [pkg/cmd/extension/command.go:694](pkg/cmd/extension/command.go#L694) - `checkValidExtension`
- Entrypoint: gh extension command
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Serve a different binary than advertised from the release host.
- Invariant to test: Binary installs verify integrity against a signed/attested value.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with a mismatched artifact asserting install failure.
