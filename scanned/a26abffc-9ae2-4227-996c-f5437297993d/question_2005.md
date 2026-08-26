# Q2005: parseQString — config key injection under extra config

## Question
Under a deployment that also passes `--git-config`, an attacker supplies a key containing a section separator or subsection quoting. In the character-level scanner helpers parseQString(), unescape(), parseGitConfigKey/Val(), can that mean a different section than intended is configured, e.g. url rewriting or transport settings, so that the invariant “keys are validated before being written” no longer holds and the outcome is transport redirection: fetches sent to an attacker-chosen host?

## Target
- File/function: [main.go](main.go) — `parseQString / unescape / parseGitConfigVal`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Supplies a key containing a section separator or subsection quoting. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a different section than intended is configured, e.g. url rewriting or transport settings
- Invariant to test: keys are validated before being written
- Expected Immunefi impact: transport redirection: fetches sent to an attacker-chosen host (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: dump `git config list -z` under GIT_CONFIG_GLOBAL after the fixture sync and assert the effective keys equal the intended set
