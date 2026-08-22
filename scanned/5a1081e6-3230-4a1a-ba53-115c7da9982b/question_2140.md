# Q2140: self-update fetches an unverified binary - getLatestReleaseInfo in update.go

## Question
Does `getLatestReleaseInfo` in [internal/update/update.go](internal/update/update.go#L115) decide on or fetch an update using data from a response (version string, URL) without pinning host and verifying integrity?

## Target
- File/function: [internal/update/update.go:115](internal/update/update.go#L115) - `getLatestReleaseInfo`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Serve a crafted release payload to the update check.
- Invariant to test: Update checks are host-pinned and any downloaded artifact is verified.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with a hostile release payload asserting no unverified fetch.
