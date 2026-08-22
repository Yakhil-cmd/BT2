# Q2012: host not validated before opening - runBrowse in browse.go

## Question
Is the host of the URL opened by `runBrowse` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L187) taken from an API response or repo metadata without checking it against the authenticated host?

## Target
- File/function: [pkg/cmd/browse/browse.go:187](pkg/cmd/browse/browse.go#L187) - `runBrowse`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Return an html_url pointing at an attacker phishing page and let the victim open it.
- Invariant to test: Opened URLs must belong to the host gh is operating against.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting a cross-host URL is refused.
