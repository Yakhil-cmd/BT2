# Q5106: TLS verification weakened on a branch - TranslateRemotes in remote.go

## Question
Is there a code path through `TranslateRemotes` in [context/remote.go](context/remote.go#L105) where a custom transport, test hook, or insecure flag disables certificate verification in a build users actually run?

## Target
- File/function: [context/remote.go:105](context/remote.go#L105) - `TranslateRemotes`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Reach the branch via normal flags/env in a release build.
- Invariant to test: TLS verification is never disabled in non-test code.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the production transport has no InsecureSkipVerify.
