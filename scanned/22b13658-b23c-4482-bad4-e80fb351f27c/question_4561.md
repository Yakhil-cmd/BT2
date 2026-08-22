# Q4561: checksum/attestation not enforced for binaries - newIOStreams in cmd.go

## Question
Does `newIOStreams` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L350) install a downloaded extension binary without verifying a checksum or attestation bound to the source repository?

## Target
- File/function: [internal/ghcmd/cmd.go:350](internal/ghcmd/cmd.go#L350) - `newIOStreams`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Serve a different binary than advertised from the release host.
- Invariant to test: Binary installs verify integrity against a signed/attested value.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with a mismatched artifact asserting install failure.
