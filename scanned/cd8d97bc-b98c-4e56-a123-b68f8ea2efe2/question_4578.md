# Q4578: world-readable secret material - lockfilePath in lockfile.go

## Question
Does `lockfilePath` in [internal/skills/lockfile/lockfile.go](internal/skills/lockfile/lockfile.go#L43) create a file that can contain a token or credential with permissive (0644/0666) mode or in a shared temp directory?

## Target
- File/function: [internal/skills/lockfile/lockfile.go:43](internal/skills/lockfile/lockfile.go#L43) - `lockfilePath`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Read the created file from another account on a shared/multi-user host after the victim runs gh skills install.
- Invariant to test: Anything that may hold credentials is created 0600 inside the user's private config dir.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Unit test asserting the FileMode of the created file is 0600 and its parent is not a shared temp dir.
