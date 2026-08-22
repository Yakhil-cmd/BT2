# Q4909: ssh arguments from remote data - (API).StopCodespace in api.go

## Question
Can values reaching `StopCodespace` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L619) (codespace name, user, port, options) be inserted into the ssh argv where they become options such as `-o ProxyCommand=`?

## Target
- File/function: [internal/codespaces/api/api.go:619](internal/codespaces/api/api.go#L619) - `(API).StopCodespace`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Name the codespace or its fields with a leading dash / embedded option.
- Invariant to test: All remote-derived values are validated and placed after `--` or passed as fixed options.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test asserting the recorded ssh argv for hostile names.
