# Q2800: non-http scheme opened - (App).VSCode in code.go

## Question
Can the URL opened by `VSCode` in [pkg/cmd/codespace/code.go](pkg/cmd/codespace/code.go#L36) come from remote data (codespace/API response fields and everything the codespace-side process sends back) and carry a scheme other than http(s) - `javascript:`, `file:`, `vscode:`, `ms-msdt:`, `smb:` - which the OS handler executes?

## Target
- File/function: [pkg/cmd/codespace/code.go:36](pkg/cmd/codespace/code.go#L36) - `(App).VSCode`
- Entrypoint: gh codespace code
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish an object whose URL field the victim opens with gh codespace code.
- Invariant to test: Only http/https URLs on validated hosts are handed to the OS opener.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test of hostile schemes asserting the opener is never called.
