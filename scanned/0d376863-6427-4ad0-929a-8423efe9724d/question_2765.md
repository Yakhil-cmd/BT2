# Q2765: URL parsed twice with different results - (API).GetOrgMemberCodespace in api.go

## Question
Does `GetOrgMemberCodespace` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L485) parse the same attacker string with two different parsers (url.Parse vs manual split vs git URL parser) so validation and use disagree?

## Target
- File/function: [internal/codespaces/api/api.go:485](internal/codespaces/api/api.go#L485) - `(API).GetOrgMemberCodespace`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Craft a URL that the two parsers read differently (`https://a@b/`, `ssh://`, `git@host:path`).
- Invariant to test: One parse result is computed once and reused for both the check and the action.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Differential fuzz test comparing both parsers on random URLs.
