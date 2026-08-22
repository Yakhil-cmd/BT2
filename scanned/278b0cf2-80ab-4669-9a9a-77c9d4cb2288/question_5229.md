# Q5229: remote resolution picks the attacker remote - (Manager).otherBinScaffolding in manager.go

## Question
Can an extra remote added by an attacker-published repository be selected by `otherBinScaffolding` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L645) as the base repo, so subsequent authenticated API calls target attacker coordinates?

## Target
- File/function: [pkg/cmd/extension/manager.go:645](pkg/cmd/extension/manager.go#L645) - `(Manager).otherBinScaffolding`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Ship a repo containing a second remote named to win gh's resolution order.
- Invariant to test: Base repo resolution prefers explicitly configured/authenticated hosts and warns on ambiguity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test in a temp repo with competing remotes asserting the expected selection.
