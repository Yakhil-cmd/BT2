# Q2929: Hookify frontmatter parser downgrade block rule via extract frontmatter

## Question
Can an unprivileged attacker while staying inside the public, unprivileged attacker model reach `extract_frontmatter` via `/hookify` and control malformed YAML frontmatter delimiters so that the codebase cause a block rule to be interpreted as warn or ignored on a dangerous tool invocation, breaking the invariant that a deny rule must never be parsed into a non-blocking configuration and leading to Security-control bypass that silently disables or routes around blocking, review, or permission boundaries?

## Target
- File/function: `plugins/hookify/core/config_loader.py` / `extract_frontmatter`
- Entrypoint: `/hookify`
- Attacker controls: malformed YAML frontmatter delimiters
- Exploit idea: Drive `/hookify` with attacker-controlled malformed YAML frontmatter delimiters and test whether `extract_frontmatter` changes security behavior in a way that cause a block rule to be interpreted as warn or ignored on a dangerous tool invocation.
- Invariant to test: a deny rule must never be parsed into a non-blocking configuration
- Expected Immunefi impact: Security-control bypass that silently disables or routes around blocking, review, or permission boundaries
- Fast validation: place a crafted .claude/hookify.*.local.md in a cloned repo, trigger the corresponding hook with Bash/Edit/Stop, and assert the parsed Rule object differs from the visible file
