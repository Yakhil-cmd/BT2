# Q1957: Hookify rule model legacy explicit differential via condition from dict

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `Condition.from_dict` via `rule-file parse during hook execution` and control frontmatter supplied by /hookify generation or a repo-shipped rule file so that the codebase exploit differences between legacy pattern parsing and explicit condition parsing to evade a block rule, breaking the invariant that legacy and explicit rule forms must produce the same effective security semantics and leading to Cross-repo, cross-session, or wrong-target mutation with real security impact?

## Target
- File/function: `plugins/hookify/core/config_loader.py` / `Condition.from_dict`
- Entrypoint: `rule-file parse during hook execution`
- Attacker controls: frontmatter supplied by /hookify generation or a repo-shipped rule file
- Exploit idea: Drive `rule-file parse during hook execution` with attacker-controlled frontmatter supplied by /hookify generation or a repo-shipped rule file and test whether `Condition.from_dict` changes security behavior in a way that exploit differences between legacy pattern parsing and explicit condition parsing to evade a block rule.
- Invariant to test: legacy and explicit rule forms must produce the same effective security semantics
- Expected Immunefi impact: Cross-repo, cross-session, or wrong-target mutation with real security impact
- Fast validation: construct adversarial Rule.from_dict and Condition.from_dict inputs and compare the resulting rule semantics against the intended policy
