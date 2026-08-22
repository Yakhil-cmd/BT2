# Q0799: token read by an untrusted child surface - AddAuthTokenHeader in http_client.go

## Question
Does `AddAuthTokenHeader` in [api/http_client.go](api/http_client.go#L152) expose the token to an extension, skill, hook, or editor process whose code came from a repo/remote/host string or API response field the attacker publishes?

## Target
- File/function: [api/http_client.go:152](api/http_client.go#L152) - `AddAuthTokenHeader`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish an extension/skill the victim installs and read GH_TOKEN from its environment.
- Invariant to test: Tokens are provided only to gh's own HTTP layer and to git for matching hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the child environment built for third-party code omits token variables.
