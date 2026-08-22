# Q0264: extension shadows a core command - getSelectedReadme in browse.go

## Question
Can an installed extension processed by `getSelectedReadme` in [pkg/cmd/extension/browse/browse.go](pkg/cmd/extension/browse/browse.go#L302) take over a built-in command name or alias, so a routine `gh auth`/`gh api` invocation runs attacker code?

## Target
- File/function: [pkg/cmd/extension/browse/browse.go:302](pkg/cmd/extension/browse/browse.go#L302) - `getSelectedReadme`
- Entrypoint: gh extension browse
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an extension named to collide with a core or newly added command.
- Invariant to test: Core command names always win and collisions are refused at install time.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test installing a colliding name asserting rejection.
