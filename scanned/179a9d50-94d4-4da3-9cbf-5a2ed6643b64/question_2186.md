# Q2186: device/web flow bound to the wrong host - getCallbackURI in flow.go

## Question
Does `getCallbackURI` in [internal/authflow/flow.go](internal/authflow/flow.go#L108) accept the OAuth endpoints (authorize/token/device URLs) from data the attacker can influence rather than deriving them from the validated host?

## Target
- File/function: [internal/authflow/flow.go:108](internal/authflow/flow.go#L108) - `getCallbackURI`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Serve endpoint metadata pointing token exchange at an attacker collector.
- Invariant to test: OAuth endpoints are derived from the validated host constant.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the token exchange URL host equals the login host.
