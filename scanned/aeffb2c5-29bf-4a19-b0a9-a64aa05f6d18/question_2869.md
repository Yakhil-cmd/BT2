# Q2869: host taken from repo remote - (cfg).PreferEditorPrompt in config.go

## Question
Does `PreferEditorPrompt` in [internal/config/config.go](internal/config/config.go#L163) accept the host embedded in a git remote URL of the repo the victim is standing in, without checking it against the authenticated hosts?

## Target
- File/function: [internal/config/config.go:163](internal/config/config.go#L163) - `(cfg).PreferEditorPrompt`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a repo whose `.git/config` remote (or submodule) points at an attacker host, then have the victim run gh auth login inside a clone.
- Invariant to test: Hosts from repository metadata are only used after matching an authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test in a temp repo with a hostile remote asserting gh refuses or does not authenticate.
