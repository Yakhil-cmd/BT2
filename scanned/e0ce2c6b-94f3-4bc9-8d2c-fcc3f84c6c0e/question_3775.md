# Q3775: Shipped skill workflow skill trigger prompt injection via plugin dev plugin settings skill

## Question
Can an unprivileged attacker through a normal cloned-repo workflow reach `plugin-dev plugin-settings skill` via `Skill tool loading plugin-settings` and control repo-controlled files that cause the Skill tool to load the skill so that the codebase shape the triggering context so the skill causes broader-than-intended file reads or tool use, breaking the invariant that loading a skill must not broaden authority beyond the user task and default trust boundaries and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/plugin-dev/skills/plugin-settings/SKILL.md` / `plugin-dev plugin-settings skill`
- Entrypoint: `Skill tool loading plugin-settings`
- Attacker controls: repo-controlled files that cause the Skill tool to load the skill
- Exploit idea: Drive `Skill tool loading plugin-settings` with attacker-controlled repo-controlled files that cause the Skill tool to load the skill and test whether `plugin-dev plugin-settings skill` changes security behavior in a way that shape the triggering context so the skill causes broader-than-intended file reads or tool use.
- Invariant to test: loading a skill must not broaden authority beyond the user task and default trust boundaries
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: trigger the skill from a malicious repo and confirm the documented workflow does not read or act on unrelated local files
