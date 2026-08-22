# Q1455: OAuth callback/state validation - (AuthConfig).activateUser in config.go

## Question
Does the browser/device flow driven by `activateUser` in [internal/config/config.go](internal/config/config.go#L460) accept a callback or device response without binding state, PKCE, or the originating host?

## Target
- File/function: [internal/config/config.go:460](internal/config/config.go#L460) - `(AuthConfig).activateUser`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Feed the local callback listener a forged request so gh stores an attacker-issued token for the victim's host.
- Invariant to test: Callbacks are accepted only with a matching state and from the flow gh initiated.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test posting a forged callback with a wrong state and asserting rejection.
