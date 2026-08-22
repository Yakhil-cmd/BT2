# Q4873: Windows argument re-splitting - Copy in ssh.go

## Question
On Windows, does the command assembled in `Copy` in [internal/codespaces/ssh.go](internal/codespaces/ssh.go#L42) re-split codespace/API response fields and everything the codespace-side process sends back because of quotes, `^`, or `&` characters passed through cmd.exe or a .bat shim?

## Target
- File/function: [internal/codespaces/ssh.go:42](internal/codespaces/ssh.go#L42) - `Copy`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a name containing `" & calc &` and let the victim on Windows run gh codespace ssh.
- Invariant to test: Arguments must survive Windows quoting rules unchanged; no cmd.exe interpretation of remote data.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Windows-tagged unit test asserting the escaped argument round-trips to the exact original string.
