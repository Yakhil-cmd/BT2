# Q3898: Shipped skill workflow skill trigger prompt injection via plugin dev plugin structure skil

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `plugin-dev plugin-structure skill` via `Skill tool loading plugin-structure` and control repo-controlled files that cause the Skill tool to load the skill so that the codebase shape the triggering context so the skill causes broader-than-intended file reads or tool use, breaking the invariant that loading a skill must not broaden authority beyond the user task and default trust boundaries and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/plugin-dev/skills/plugin-structure/SKILL.md` / `plugin-dev plugin-structure skill`
- Entrypoint: `Skill tool loading plugin-structure`
- Attacker controls: repo-controlled files that cause the Skill tool to load the skill
- Exploit idea: Drive `Skill tool loading plugin-structure` with attacker-controlled repo-controlled files that cause the Skill tool to load the skill and test whether `plugin-dev plugin-structure skill` changes security behavior in a way that shape the triggering context so the skill causes broader-than-intended file reads or tool use.
- Invariant to test: loading a skill must not broaden authority beyond the user task and default trust boundaries
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: trigger the skill from a malicious repo and confirm the documented workflow does not read or act on unrelated local files
