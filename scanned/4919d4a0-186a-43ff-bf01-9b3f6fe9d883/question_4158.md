# Q4158: host not validated before opening - New in browser.go

## Question
Is the host of the URL opened by `New` in [internal/browser/browser.go](internal/browser/browser.go#L13) taken from an API response or repo metadata without checking it against the authenticated host?

## Target
- File/function: [internal/browser/browser.go:13](internal/browser/browser.go#L13) - `New`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Return an html_url pointing at an attacker phishing page and let the victim open it.
- Invariant to test: Opened URLs must belong to the host gh is operating against.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting a cross-host URL is refused.
