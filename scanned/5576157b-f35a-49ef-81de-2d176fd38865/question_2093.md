# Q2093: ssh arguments from remote data - (codespace).running in common.go

## Question
Can values reaching `running` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L231) (codespace name, user, port, options) be inserted into the ssh argv where they become options such as `-o ProxyCommand=`?

## Target
- File/function: [pkg/cmd/codespace/common.go:231](pkg/cmd/codespace/common.go#L231) - `(codespace).running`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Name the codespace or its fields with a leading dash / embedded option.
- Invariant to test: All remote-derived values are validated and placed after `--` or passed as fixed options.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test asserting the recorded ssh argv for hostile names.
