# Q2088: newline/control chars in the URL - (App).Jupyter in jupyter.go

## Question
Does `Jupyter` in [pkg/cmd/codespace/jupyter.go](pkg/cmd/codespace/jupyter.go#L32) accept a URL containing CR/LF or NUL from remote data before invoking the opener?

## Target
- File/function: [pkg/cmd/codespace/jupyter.go:32](pkg/cmd/codespace/jupyter.go#L32) - `(App).Jupyter`
- Entrypoint: gh codespace jupyter
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a URL with `%0a` that splits into a second command on some platforms.
- Invariant to test: URLs with control characters are rejected.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Fuzz test asserting rejection of control characters.
