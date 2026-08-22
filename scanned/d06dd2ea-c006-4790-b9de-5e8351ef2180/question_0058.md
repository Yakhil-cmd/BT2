# Q0058: git output parsed as trusted - NewCmdSetupGit in setupgit.go

## Question
Does `NewCmdSetupGit` in [pkg/cmd/auth/setupgit/setupgit.go](pkg/cmd/auth/setupgit/setupgit.go#L27) parse git stdout that a hostile repository can shape (branch names, remote lists, config values) and use it for a host or path decision?

## Target
- File/function: [pkg/cmd/auth/setupgit/setupgit.go:27](pkg/cmd/auth/setupgit/setupgit.go#L27) - `NewCmdSetupGit`
- Entrypoint: gh auth setupgit
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a repo whose branch names embed delimiters used by gh's parser.
- Invariant to test: Git output is parsed with NUL-delimited/porcelain formats and validated.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with delimiter-bearing names asserting correct parsing.
