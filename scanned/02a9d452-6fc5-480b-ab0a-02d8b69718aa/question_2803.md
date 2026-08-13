# Q2803: Shipped skill workflow skill trigger prompt injection via claude opus 4 5 migration skill

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `claude-opus-4-5-migration skill` via `Skill tool loading claude-opus-4-5-migration` and control repo-controlled files that cause the Skill tool to load the skill so that the codebase shape the triggering context so the skill causes broader-than-intended file reads or tool use, breaking the invariant that skill instructions must not let lower-trust repo content suppress baseline safety expectations and leading to Security-control bypass that silently disables or routes around blocking, review, or permission boundaries?

## Target
- File/function: `plugins/claude-opus-4-5-migration/skills/claude-opus-4-5-migration/SKILL.md` / `claude-opus-4-5-migration skill`
- Entrypoint: `Skill tool loading claude-opus-4-5-migration`
- Attacker controls: repo-controlled files that cause the Skill tool to load the skill
- Exploit idea: Drive `Skill tool loading claude-opus-4-5-migration` with attacker-controlled repo-controlled files that cause the Skill tool to load the skill and test whether `claude-opus-4-5-migration skill` changes security behavior in a way that shape the triggering context so the skill causes broader-than-intended file reads or tool use.
- Invariant to test: skill instructions must not let lower-trust repo content suppress baseline safety expectations
- Expected Immunefi impact: Security-control bypass that silently disables or routes around blocking, review, or permission boundaries
- Fast validation: trigger the skill from a malicious repo and confirm the documented workflow does not read or act on unrelated local files
