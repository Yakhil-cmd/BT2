# Q3905: Hookify frontmatter parser downgrade block rule via extract frontmatter

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `extract_frontmatter` via `/hookify` and control malformed YAML frontmatter delimiters so that the codebase cause a block rule to be interpreted as warn or ignored on a dangerous tool invocation, breaking the invariant that rule semantics must not change because of formatting ambiguity and leading to Unauthorized file read or write outside the user-approved workspace or target scope?

## Target
- File/function: `plugins/hookify/core/config_loader.py` / `extract_frontmatter`
- Entrypoint: `/hookify`
- Attacker controls: malformed YAML frontmatter delimiters
- Exploit idea: Drive `/hookify` with attacker-controlled malformed YAML frontmatter delimiters and test whether `extract_frontmatter` changes security behavior in a way that cause a block rule to be interpreted as warn or ignored on a dangerous tool invocation.
- Invariant to test: rule semantics must not change because of formatting ambiguity
- Expected Immunefi impact: Unauthorized file read or write outside the user-approved workspace or target scope
- Fast validation: place a crafted .claude/hookify.*.local.md in a cloned repo, trigger the corresponding hook with Bash/Edit/Stop, and assert the parsed Rule object differs from the visible file
