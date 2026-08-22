# Q0505: terminal command injection via escape - writeTSV in read_dir.go

## Question
Can attacker-supplied text rendered by `writeTSV` in [pkg/cmd/repo/read-dir/read_dir.go](pkg/cmd/repo/read-dir/read_dir.go#L154) carry sequences that terminals execute or auto-report (OSC 8 with a non-http URI, bracketed-paste break, title-set-then-report), turning display into command execution?

## Target
- File/function: [pkg/cmd/repo/read-dir/read_dir.go:154](pkg/cmd/repo/read-dir/read_dir.go#L154) - `writeTSV`
- Entrypoint: gh repo read-dir
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Embed the payload in a PR title/body/check output the victim displays.
- Invariant to test: Only a safe subset of styling is emitted; hyperlinks are restricted to http(s).
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting rendered hyperlinks/URIs are scheme-checked and controls stripped.
