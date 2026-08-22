# Q5513: non-http scheme opened - viewRun in view.go

## Question
Can the URL opened by `viewRun` in [pkg/cmd/gist/view/view.go](pkg/cmd/gist/view/view.go#L81) come from remote data (an asset, artifact, gist, or archive-member name and its bytes) and carry a scheme other than http(s) - `javascript:`, `file:`, `vscode:`, `ms-msdt:`, `smb:` - which the OS handler executes?

## Target
- File/function: [pkg/cmd/gist/view/view.go:81](pkg/cmd/gist/view/view.go#L81) - `viewRun`
- Entrypoint: gh gist view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an object whose URL field the victim opens with gh gist view.
- Invariant to test: Only http/https URLs on validated hosts are handed to the OS opener.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test of hostile schemes asserting the opener is never called.
