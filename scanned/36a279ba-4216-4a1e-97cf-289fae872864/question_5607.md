# Q5607: token read by an untrusted child surface - connect in invoker.go

## Question
Does `connect` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L77) expose the token to an extension, skill, hook, or editor process whose code came from codespace/API response fields and everything the codespace-side process sends back?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:77](internal/codespaces/rpc/invoker.go#L77) - `connect`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish an extension/skill the victim installs and read GH_TOKEN from its environment.
- Invariant to test: Tokens are provided only to gh's own HTTP layer and to git for matching hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the child environment built for third-party code omits token variables.
