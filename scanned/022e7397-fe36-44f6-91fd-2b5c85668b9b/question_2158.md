# Q2158: main (GIT_CONFIG_GLOBAL setup) — config key injection under submodules recursive

## Question
Does the private gitconfig tempfile plus GIT_CONFIG_NOSYSTEM, and the `git config list -z` dump that is logged stay safe when an attacker supplies a key containing a section separator or subsection quoting in the default `--submodules=recursive`, so config affects submodule transports — or can a different section than intended is configured, e.g. url rewriting or transport settings, violating “keys are validated before being written” and producing transport redirection: fetches sent to an attacker-chosen host?

## Target
- File/function: [main.go](main.go) — `main (GIT_CONFIG_GLOBAL setup)`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Supplies a key containing a section separator or subsection quoting. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a different section than intended is configured, e.g. url rewriting or transport settings
- Invariant to test: keys are validated before being written
- Expected Immunefi impact: transport redirection: fetches sent to an attacker-chosen host (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: fuzz parseGitConfigs() against git's own parser and assert identical key/value pairs or a clean error
