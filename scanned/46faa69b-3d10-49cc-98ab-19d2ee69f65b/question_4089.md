# Q4089: browser value used without validation - createRun in create.go

## Question
Does `createRun` in [pkg/cmd/gist/create/create.go](pkg/cmd/gist/create/create.go#L108) resolve the browser command from data that a remote object (skill, extension manifest, codespace config) can influence rather than only from the user's own environment?

## Target
- File/function: [pkg/cmd/gist/create/create.go:108](pkg/cmd/gist/create/create.go#L108) - `createRun`
- Entrypoint: gh gist create
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish content that sets the browser field consumed by this code path.
- Invariant to test: The opener command comes only from local user configuration.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting remote-sourced values are ignored.
