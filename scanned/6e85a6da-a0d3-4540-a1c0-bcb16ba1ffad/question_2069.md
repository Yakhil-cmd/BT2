# Q2069: Shipped skill workflow skill trigger prompt injection via plugin dev skill development ski

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `plugin-dev skill-development skill` via `Skill tool loading skill-development` and control repo-controlled files that cause the Skill tool to load the skill so that the codebase shape the triggering context so the skill causes broader-than-intended file reads or tool use, breaking the invariant that skill instructions must not let lower-trust repo content suppress baseline safety expectations and leading to Cross-repo, cross-session, or wrong-target mutation with real security impact?

## Target
- File/function: `plugins/plugin-dev/skills/skill-development/SKILL.md` / `plugin-dev skill-development skill`
- Entrypoint: `Skill tool loading skill-development`
- Attacker controls: repo-controlled files that cause the Skill tool to load the skill
- Exploit idea: Drive `Skill tool loading skill-development` with attacker-controlled repo-controlled files that cause the Skill tool to load the skill and test whether `plugin-dev skill-development skill` changes security behavior in a way that shape the triggering context so the skill causes broader-than-intended file reads or tool use.
- Invariant to test: skill instructions must not let lower-trust repo content suppress baseline safety expectations
- Expected Immunefi impact: Cross-repo, cross-session, or wrong-target mutation with real security impact
- Fast validation: trigger the skill from a malicious repo and confirm the documented workflow does not read or act on unrelated local files
