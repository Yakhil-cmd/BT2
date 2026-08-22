# Q0150: ref name starting with a dash - ParseRemoteTrackingRef in client.go

## Question
Does `ParseRemoteTrackingRef` in [git/client.go](git/client.go#L604) place a branch/ref/tag name from remote data in a git argv position where a leading `-` becomes an option (e.g. `--upload-pack=`)?

## Target
- File/function: [git/client.go:604](git/client.go#L604) - `ParseRemoteTrackingRef`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a PR branch or tag named `--upload-pack=touch /tmp/pwn`.
- Invariant to test: Ref values are validated against git's ref format and always follow `--`.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test with hostile ref names asserting rejection or correct positioning.
