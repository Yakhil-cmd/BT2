# Q4522: argv injection into subprocess - codesignBinary in manager.go

## Question
Can an unprivileged attacker publish an extension repository, its release assets, and its manifest fields that reaches `codesignBinary` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L854) and is appended to the subprocess argv without a `--` terminator, so a leading-dash value is parsed as an option by the spawned program?

## Target
- File/function: [pkg/cmd/extension/manager.go:854](pkg/cmd/extension/manager.go#L854) - `codesignBinary`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a repo/branch/asset whose name begins with `--` (e.g. `--upload-pack=touch /tmp/pwn`) and let the victim run gh extension manager.
- Invariant to test: No value derived from remote data may be positioned where the child process can interpret it as a flag.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table-driven Go test stubbing the command runner; assert the recorded argv places attacker input after `--` and never as argv[i] starting with `-`.
