# Q2998: PR head from a fork controls checkout args - parseWorktrees in client.go

## Question
Does `parseWorktrees` in [git/client.go](git/client.go#L294) build the fetch/checkout arguments from the PR's headRefName/headRepository fields, which any unprivileged user can choose when opening a PR against the victim's repo?

## Target
- File/function: [git/client.go:294](git/client.go#L294) - `parseWorktrees`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Open a PR whose head ref/repo name embeds options or traversal, then wait for a maintainer to run gh repo clone.
- Invariant to test: PR-derived names are validated before use in argv or paths.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with a hostile PR fixture asserting the recorded git argv.
