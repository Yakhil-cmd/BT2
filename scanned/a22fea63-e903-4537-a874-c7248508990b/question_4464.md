# Q4464: gh-specific post-clone git commands - executeRemoteRepoSync in sync.go

## Question
Can attacker-controlled repository metadata (default branch name, remote list, upstream) influence the extra git commands gh runs after gh repo sync through `executeRemoteRepoSync` in [pkg/cmd/repo/sync/sync.go](pkg/cmd/repo/sync/sync.go#L281)?

## Target
- File/function: [pkg/cmd/repo/sync/sync.go:281](pkg/cmd/repo/sync/sync.go#L281) - `executeRemoteRepoSync`
- Entrypoint: gh repo sync
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Set a default branch named `--exec=...` or containing shell-relevant characters.
- Invariant to test: Names from remote data are validated as refs and passed after `--`.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test of hostile default-branch names.
