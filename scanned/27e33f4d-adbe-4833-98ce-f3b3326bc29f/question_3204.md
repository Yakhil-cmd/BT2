# Q3204: unbounded output buffering - printPreInstallDisclaimer in install.go

## Question
Does `printPreInstallDisclaimer` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L1189) accumulate the full attacker-controlled body/table in memory before printing, allowing a huge published object to exhaust the victim's RAM?

## Target
- File/function: [pkg/cmd/skills/install/install.go:1189](pkg/cmd/skills/install/install.go#L1189) - `printPreInstallDisclaimer`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish an object with an enormous field the victim lists or views.
- Invariant to test: Rendering streams with bounded buffers.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark/test with a very large field asserting bounded allocation or an error.
