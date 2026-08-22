# Q4941: argument splitting in the OS opener - (App).VSCode in code.go

## Question
Does `VSCode` in [pkg/cmd/codespace/code.go](pkg/cmd/codespace/code.go#L36) pass the URL to `open`/`xdg-open`/`cmd /c start` in a way that lets embedded quotes, `&`, or leading `-` become extra arguments?

## Target
- File/function: [pkg/cmd/codespace/code.go:36](pkg/cmd/codespace/code.go#L36) - `(App).VSCode`
- Entrypoint: gh codespace code
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a URL containing `" & calc &` for Windows victims.
- Invariant to test: The URL is passed as a single argv element after scheme/host validation.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Stub-runner test asserting exactly one URL argument, unsplit.
