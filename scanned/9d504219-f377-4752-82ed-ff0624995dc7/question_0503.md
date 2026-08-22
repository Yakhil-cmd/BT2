# Q0503: content type/extension confusion - NewCmdReadDir in read_dir.go

## Question
Does `NewCmdReadDir` in [pkg/cmd/repo/read-dir/read_dir.go](pkg/cmd/repo/read-dir/read_dir.go#L44) preserve an attacker-chosen extension (.command, .desktop, .lnk, .bat, .scpt) or set an executable mode on downloaded content?

## Target
- File/function: [pkg/cmd/repo/read-dir/read_dir.go:44](pkg/cmd/repo/read-dir/read_dir.go#L44) - `NewCmdReadDir`
- Entrypoint: gh repo read-dir
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an asset named to be executable/auto-runnable on the victim's platform.
- Invariant to test: Downloaded files are written non-executable with the name shown to the user.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting file mode and final name.
