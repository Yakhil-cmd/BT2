# Q2210: git output parsed as trusted - (HelperConfig).ConfiguredHelper in helper_config.go

## Question
Does `ConfiguredHelper` in [pkg/cmd/auth/shared/gitcredentials/helper_config.go](pkg/cmd/auth/shared/gitcredentials/helper_config.go#L92) parse git stdout that a hostile repository can shape (branch names, remote lists, config values) and use it for a host or path decision?

## Target
- File/function: [pkg/cmd/auth/shared/gitcredentials/helper_config.go:92](pkg/cmd/auth/shared/gitcredentials/helper_config.go#L92) - `(HelperConfig).ConfiguredHelper`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a repo whose branch names embed delimiters used by gh's parser.
- Invariant to test: Git output is parsed with NUL-delimited/porcelain formats and validated.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with delimiter-bearing names asserting correct parsing.
