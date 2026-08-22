# Q5097: YAML/frontmatter expansion or injection - FromFullNameWithHost in repo.go

## Question
Does the frontmatter/YAML parsing in `FromFullNameWithHost` in [internal/ghrepo/repo.go](internal/ghrepo/repo.go#L52) allow anchors/aliases, duplicate keys, or unexpected fields from remote content to override a validated value?

## Target
- File/function: [internal/ghrepo/repo.go:52](internal/ghrepo/repo.go#L52) - `FromFullNameWithHost`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a skill/template whose frontmatter redefines a field gh already validated.
- Invariant to test: Parsing is strict: known fields only, duplicates and aliases rejected.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with duplicate/alias frontmatter asserting an error.
