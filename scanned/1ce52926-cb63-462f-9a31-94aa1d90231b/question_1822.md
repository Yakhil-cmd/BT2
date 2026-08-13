# Q1822: Shipped skill workflow skill trigger prompt injection via plugin dev mcp integration skill

## Question
Can an unprivileged attacker while staying inside the public, unprivileged attacker model reach `plugin-dev mcp-integration skill` via `Skill tool loading mcp-integration` and control repo-controlled files that cause the Skill tool to load the skill so that the codebase shape the triggering context so the skill causes broader-than-intended file reads or tool use, breaking the invariant that skill instructions must not let lower-trust repo content suppress baseline safety expectations and leading to Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink?

## Target
- File/function: `plugins/plugin-dev/skills/mcp-integration/SKILL.md` / `plugin-dev mcp-integration skill`
- Entrypoint: `Skill tool loading mcp-integration`
- Attacker controls: repo-controlled files that cause the Skill tool to load the skill
- Exploit idea: Drive `Skill tool loading mcp-integration` with attacker-controlled repo-controlled files that cause the Skill tool to load the skill and test whether `plugin-dev mcp-integration skill` changes security behavior in a way that shape the triggering context so the skill causes broader-than-intended file reads or tool use.
- Invariant to test: skill instructions must not let lower-trust repo content suppress baseline safety expectations
- Expected Immunefi impact: Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink
- Fast validation: trigger the skill from a malicious repo and confirm the documented workflow does not read or act on unrelated local files
