# Q0517: content type/extension confusion - viewRun in view.go

## Question
Does `viewRun` in [pkg/cmd/gist/view/view.go](pkg/cmd/gist/view/view.go#L81) preserve an attacker-chosen extension (.command, .desktop, .lnk, .bat, .scpt) or set an executable mode on downloaded content?

## Target
- File/function: [pkg/cmd/gist/view/view.go:81](pkg/cmd/gist/view/view.go#L81) - `viewRun`
- Entrypoint: gh gist view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an asset named to be executable/auto-runnable on the victim's platform.
- Invariant to test: Downloaded files are written non-executable with the name shown to the user.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting file mode and final name.
