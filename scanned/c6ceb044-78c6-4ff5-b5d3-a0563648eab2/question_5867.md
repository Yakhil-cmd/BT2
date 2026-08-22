# Q5867: extension shadows a core command - writeManifest in manager.go

## Question
Can an installed extension processed by `writeManifest` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L394) take over a built-in command name or alias, so a routine `gh auth`/`gh api` invocation runs attacker code?

## Target
- File/function: [pkg/cmd/extension/manager.go:394](pkg/cmd/extension/manager.go#L394) - `writeManifest`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an extension named to collide with a core or newly added command.
- Invariant to test: Core command names always win and collisions are refused at install time.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test installing a colliding name asserting rejection.
