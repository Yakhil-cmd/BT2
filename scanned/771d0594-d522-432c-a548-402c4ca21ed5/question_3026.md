# Q3026: PR head from a fork controls checkout args - NewCmdFork in fork.go

## Question
Does `NewCmdFork` in [pkg/cmd/repo/fork/fork.go](pkg/cmd/repo/fork/fork.go#L64) build the fetch/checkout arguments from the PR's headRefName/headRepository fields, which any unprivileged user can choose when opening a PR against the victim's repo?

## Target
- File/function: [pkg/cmd/repo/fork/fork.go:64](pkg/cmd/repo/fork/fork.go#L64) - `NewCmdFork`
- Entrypoint: gh repo fork
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Open a PR whose head ref/repo name embeds options or traversal, then wait for a maintainer to run gh repo fork.
- Invariant to test: PR-derived names are validated before use in argv or paths.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with a hostile PR fixture asserting the recorded git argv.
