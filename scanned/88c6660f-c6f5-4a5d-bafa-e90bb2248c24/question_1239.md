# Q1239: readLowestScannedVoteNumCached unauthorized governance effect

## Question
Can an unprivileged attacker reach `readLowestScannedVoteNumCached` through permissionless transaction or block or header metadata reaching system-transition logic using governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata and make `readLowestScannedVoteNumCached` mutate protected protocol parameters without the required authority actually existing, causing the invariant that protected governance state must change only under the exact authorized vote or contract path to fail and leading to Unauthorized transaction?

## Target
- File/function: kaiax/valset/impl/getter_council.go:80 (readLowestScannedVoteNumCached)
- Entrypoint: permissionless transaction or block or header metadata reaching system-transition logic
- Attacker controls: governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata
- Exploit idea: make `readLowestScannedVoteNumCached` mutate protected protocol parameters without the required authority actually existing
- Invariant to test: protected governance state must change only under the exact authorized vote or contract path
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: inject malformed governance payloads in a local private network and assert parameters cannot change without authorized origin and quorum
