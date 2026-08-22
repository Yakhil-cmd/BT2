# Q0515: content type/extension confusion - getFilesToAdd in edit.go

## Question
Does `getFilesToAdd` in [pkg/cmd/gist/edit/edit.go](pkg/cmd/gist/edit/edit.go#L420) preserve an attacker-chosen extension (.command, .desktop, .lnk, .bat, .scpt) or set an executable mode on downloaded content?

## Target
- File/function: [pkg/cmd/gist/edit/edit.go:420](pkg/cmd/gist/edit/edit.go#L420) - `getFilesToAdd`
- Entrypoint: gh gist edit
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an asset named to be executable/auto-runnable on the victim's platform.
- Invariant to test: Downloaded files are written non-executable with the name shown to the user.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting file mode and final name.
