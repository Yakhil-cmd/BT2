# Q1233: newline/control chars in the URL - createRun in create.go

## Question
Does `createRun` in [pkg/cmd/gist/create/create.go](pkg/cmd/gist/create/create.go#L108) accept a URL containing CR/LF or NUL from remote data before invoking the opener?

## Target
- File/function: [pkg/cmd/gist/create/create.go:108](pkg/cmd/gist/create/create.go#L108) - `createRun`
- Entrypoint: gh gist create
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a URL with `%0a` that splits into a second command on some platforms.
- Invariant to test: URLs with control characters are rejected.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Fuzz test asserting rejection of control characters.
