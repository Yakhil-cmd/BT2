# Q2424: stale/pinned version downgrade - (cmdWithStderr).Run in run.go

## Question
Can an attacker who controls the extension repository make `Run` in [internal/run/run.go](internal/run/run.go#L52) install an older, known-vulnerable version or skip the pin recorded locally?

## Target
- File/function: [internal/run/run.go:52](internal/run/run.go#L52) - `(cmdWithStderr).Run`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Re-tag the release so the resolved version differs from the pin.
- Invariant to test: Version resolution is pinned and monotonic, verified after download.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting the installed version matches the pin.
