# Q2381: Windows argument re-splitting - codesignBinary in manager.go

## Question
On Windows, does the command assembled in `codesignBinary` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L854) re-split an extension repository, its release assets, and its manifest fields because of quotes, `^`, or `&` characters passed through cmd.exe or a .bat shim?

## Target
- File/function: [pkg/cmd/extension/manager.go:854](pkg/cmd/extension/manager.go#L854) - `codesignBinary`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a name containing `" & calc &` and let the victim on Windows run gh extension manager.
- Invariant to test: Arguments must survive Windows quoting rules unchanged; no cmd.exe interpretation of remote data.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Windows-tagged unit test asserting the escaped argument round-trips to the exact original string.
