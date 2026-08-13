# Q980: Hookify rule model legacy explicit differential via rule from dict

## Question
Can an unprivileged attacker without maintainer, admin, or leaked-credential assumptions reach `Rule.from_dict` via `/hookify rule creation` and control frontmatter supplied by /hookify generation or a repo-shipped rule file so that the codebase exploit differences between legacy pattern parsing and explicit condition parsing to evade a block rule, breaking the invariant that legacy and explicit rule forms must produce the same effective security semantics and leading to Unauthorized file read or write outside the user-approved workspace or target scope?

## Target
- File/function: `plugins/hookify/core/config_loader.py` / `Rule.from_dict`
- Entrypoint: `/hookify rule creation`
- Attacker controls: frontmatter supplied by /hookify generation or a repo-shipped rule file
- Exploit idea: Drive `/hookify rule creation` with attacker-controlled frontmatter supplied by /hookify generation or a repo-shipped rule file and test whether `Rule.from_dict` changes security behavior in a way that exploit differences between legacy pattern parsing and explicit condition parsing to evade a block rule.
- Invariant to test: legacy and explicit rule forms must produce the same effective security semantics
- Expected Immunefi impact: Unauthorized file read or write outside the user-approved workspace or target scope
- Fast validation: construct adversarial Rule.from_dict and Condition.from_dict inputs and compare the resulting rule semantics against the intended policy
