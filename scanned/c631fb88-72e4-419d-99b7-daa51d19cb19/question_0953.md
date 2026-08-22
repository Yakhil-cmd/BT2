# Q0953: git -c config injection - codesignBinary in manager.go

## Question
Can an extension repository, its release assets, and its manifest fields reach `codesignBinary` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L854) and land inside a `-c key=value` / config argument, letting an attacker set an execution-bearing git config such as `core.fsmonitor`, `core.sshCommand`, `protocol.ext.allow`, or an alias?

## Target
- File/function: [pkg/cmd/extension/manager.go:854](pkg/cmd/extension/manager.go#L854) - `codesignBinary`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a repo or ref whose name embeds `=` and newline characters so the assembled config pair splits into an extra execution-bearing key.
- Invariant to test: Config keys and values sent to git are fixed by gh, never assembled from remote strings.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Fuzz the argument builder with names containing `=`, newline, and NUL; assert only allowlisted config keys are emitted.
