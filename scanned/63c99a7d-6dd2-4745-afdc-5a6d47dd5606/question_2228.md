# Q2228: ANSI/OSC escape passthrough - ExtractHeader in http_client.go

## Question
Does `ExtractHeader` in [api/http_client.go](api/http_client.go#L175) print server-supplied text (a repo/remote/host string or API response field the attacker publishes) to the terminal without stripping C0/C1 control and ANSI/OSC sequences?

## Target
- File/function: [api/http_client.go:175](api/http_client.go#L175) - `ExtractHeader`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Put OSC 52 (clipboard write) or DCS/OSC 7 sequences in an issue/PR/release field the victim views with any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...).
- Invariant to test: All remote text is sanitized of control sequences before reaching a terminal.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test asserting escape bytes in the input are absent from rendered output.
