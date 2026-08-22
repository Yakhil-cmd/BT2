# Q4393: HTTP method/route confusion from user input - TranslateRemotes in remote.go

## Question
Can a repo/remote/host string or API response field the attacker publishes reaching `TranslateRemotes` in [context/remote.go](context/remote.go#L105) change the effective route (path traversal in the API path, extra query parameters) so a read command performs a write?

## Target
- File/function: [context/remote.go:105](context/remote.go#L105) - `TranslateRemotes`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish an object whose name embeds `../` and reaches the path builder.
- Invariant to test: Path segments are escaped; methods are fixed per operation.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting the resulting method+path for hostile names.
