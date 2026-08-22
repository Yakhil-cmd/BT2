# Q5656: browser value used without validation - (App).Jupyter in jupyter.go

## Question
Does `Jupyter` in [pkg/cmd/codespace/jupyter.go](pkg/cmd/codespace/jupyter.go#L32) resolve the browser command from data that a remote object (skill, extension manifest, codespace config) can influence rather than only from the user's own environment?

## Target
- File/function: [pkg/cmd/codespace/jupyter.go:32](pkg/cmd/codespace/jupyter.go#L32) - `(App).Jupyter`
- Entrypoint: gh codespace jupyter
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish content that sets the browser field consumed by this code path.
- Invariant to test: The opener command comes only from local user configuration.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting remote-sourced values are ignored.
