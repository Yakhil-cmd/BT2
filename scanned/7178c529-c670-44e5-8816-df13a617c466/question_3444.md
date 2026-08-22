# Q3444: argument splitting in the OS opener - New in browser.go

## Question
Does `New` in [internal/browser/browser.go](internal/browser/browser.go#L13) pass the URL to `open`/`xdg-open`/`cmd /c start` in a way that lets embedded quotes, `&`, or leading `-` become extra arguments?

## Target
- File/function: [internal/browser/browser.go:13](internal/browser/browser.go#L13) - `New`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a URL containing `" & calc &` for Windows victims.
- Invariant to test: The URL is passed as a single argv element after scheme/host validation.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Stub-runner test asserting exactly one URL argument, unsplit.
