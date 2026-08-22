# Q0588: browser value used without validation - New in browser.go

## Question
Does `New` in [internal/browser/browser.go](internal/browser/browser.go#L13) resolve the browser command from data that a remote object (skill, extension manifest, codespace config) can influence rather than only from the user's own environment?

## Target
- File/function: [internal/browser/browser.go:13](internal/browser/browser.go#L13) - `New`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish content that sets the browser field consumed by this code path.
- Invariant to test: The opener command comes only from local user configuration.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting remote-sourced values are ignored.
