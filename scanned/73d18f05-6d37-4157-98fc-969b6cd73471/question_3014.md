# Q3014: argv injection into subprocess - resolveGitPath in client.go

## Question
Can an unprivileged attacker publish a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes that reaches `resolveGitPath` in [git/client.go](git/client.go#L944) and is appended to the subprocess argv without a `--` terminator, so a leading-dash value is parsed as an option by the spawned program?

## Target
- File/function: [git/client.go:944](git/client.go#L944) - `resolveGitPath`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo/branch/asset whose name begins with `--` (e.g. `--upload-pack=touch /tmp/pwn`) and let the victim run gh repo clone.
- Invariant to test: No value derived from remote data may be positioned where the child process can interpret it as a flag.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table-driven Go test stubbing the command runner; assert the recorded argv places attacker input after `--` and never as argv[i] starting with `-`.
