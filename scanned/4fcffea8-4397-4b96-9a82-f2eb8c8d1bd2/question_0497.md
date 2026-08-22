# Q0497: content type/extension confusion - ExtractZip in zip.go

## Question
Does `ExtractZip` in [internal/zip/zip.go](internal/zip/zip.go#L24) preserve an attacker-chosen extension (.command, .desktop, .lnk, .bat, .scpt) or set an executable mode on downloaded content?

## Target
- File/function: [internal/zip/zip.go:24](internal/zip/zip.go#L24) - `ExtractZip`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an asset named to be executable/auto-runnable on the victim's platform.
- Invariant to test: Downloaded files are written non-executable with the name shown to the user.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting file mode and final name.
