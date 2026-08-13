# Q3054: Hookify rule model legacy explicit differential via rule from dict

## Question
Can an unprivileged attacker through a normal cloned-repo workflow reach `Rule.from_dict` via `/hookify rule creation` and control frontmatter supplied by /hookify generation or a repo-shipped rule file so that the codebase exploit differences between legacy pattern parsing and explicit condition parsing to evade a block rule, breaking the invariant that default field inference must not broaden rule scope or weaken enforcement and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/hookify/core/config_loader.py` / `Rule.from_dict`
- Entrypoint: `/hookify rule creation`
- Attacker controls: frontmatter supplied by /hookify generation or a repo-shipped rule file
- Exploit idea: Drive `/hookify rule creation` with attacker-controlled frontmatter supplied by /hookify generation or a repo-shipped rule file and test whether `Rule.from_dict` changes security behavior in a way that exploit differences between legacy pattern parsing and explicit condition parsing to evade a block rule.
- Invariant to test: default field inference must not broaden rule scope or weaken enforcement
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: construct adversarial Rule.from_dict and Condition.from_dict inputs and compare the resulting rule semantics against the intended policy
