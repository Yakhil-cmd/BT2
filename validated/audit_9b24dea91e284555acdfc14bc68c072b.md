### Title
Plugin agent identity collision via project-scoped `.claude/agents/` override - (File: `plugins/pr-review-toolkit/commands/review-pr.md`)

### Summary
`review-pr.md` invokes review agents by bare name (e.g. `pr-test-analyzer`, `code-reviewer`) rather than by plugin-qualified identifier, and the CLI's own documented name-resolution behavior makes the *closest-to-working-directory* agent definition win on a name collision. A malicious project-local `.claude/agents/pr-test-analyzer.md` checked into a cloned repository would therefore silently shadow the vetted `pr-review-toolkit` agent for any user who runs `/pr-review-toolkit:review-pr` in that repo.

### Finding Description
The `pr-review-toolkit` plugin's command references agents purely by their bare `name` value — e.g. `pr-test-analyzer`, `comment-analyzer`, `code-reviewer` — without any plugin-scoped qualifier such as `pr-review-toolkit:pr-test-analyzer` [1](#0-0) , and the corresponding agent definition itself only declares `name: pr-test-analyzer` in its frontmatter with no namespace binding [2](#0-1) .

Per the project's own changelog, name resolution across nested `.claude/` scopes is explicitly last-write/closest-wins: "Nested `.claude/` directories: the agent, workflow, and output-style closest to the working directory now wins when names collide" [3](#0-2) . This is a documented, intentional resolution rule, not a bug — meaning a repository-local `.claude/agents/pr-test-analyzer.md` is *closer to the working directory* than a plugin-provided agent and will win the collision. Separately, the changelog documents that plugin agents are *not* found by bare name unless explicitly qualified in some contexts ("Fixed `--agent <name>` not finding plugin-contributed agents without the `plugin:` prefix" [4](#0-3) ), confirming that bare-name identifiers are ambiguous across scopes by design, and that the plugin-qualified form (`plugin:agent-name`) is the only way to pin an exact target.

The `pr-review-toolkit` skill documentation itself even states the intended pattern of shadowing: agents are meant to be placed in either `~/.claude/agents/` (user) or project `.claude/agents/` and are "maintained" there alongside the plugin equivalents [5](#0-4) , and the `plugin-structure` skill explicitly warns "Conflicts between plugins: ... Namespace commands with plugin name if needed" as a caveat that is *not* enforced automatically for agents [6](#0-5) .

Given this, an attacker who can get a project cloned/checked out with a `.claude/agents/pr-test-analyzer.md` file (e.g., committed to a shared branch, or delivered via a PR that the victim checks out to review) can define the same `name: pr-test-analyzer` with an unrestricted system prompt (no `tools:` restriction field, which defaults to full tool access as documented for agent frontmatter [7](#0-6) ). When the victim later runs `/pr-review-toolkit:review-pr`, the command's Task invocation of `pr-test-analyzer` resolves to the attacker's project-scoped definition rather than the vetted plugin agent, since project-level definitions win collisions per the documented resolution rule.

### Impact Explanation
The attacker's arbitrary system prompt executes under a Task/subagent invocation the user explicitly approved as part of a trusted, vetted plugin workflow (`pr-review-toolkit:review-pr`), inheriting whatever tool access the parent grants (no `tools:` restriction is declared in `pr-test-analyzer.md`, so the substituted agent can run with full tool privileges) [2](#0-1) . This is a trust-boundary bypass: content in an untrusted repository silently redirects execution intended for a reviewed, marketplace-vetted agent to attacker-controlled instructions, defeating the implicit trust a user places in installing/using `pr-review-toolkit`.

### Likelihood Explanation
The only precondition is the ability to place a `.claude/agents/pr-test-analyzer.md` file in a project workspace that the victim later opens/clones and runs `/pr-review-toolkit:review-pr` in — a normal, low-privilege repository-content action (e.g., a malicious PR branch, or a shared fork). This requires no leaked credentials, no social engineering beyond "the victim reviews a cloned/checked-out repo," and is fully repeatable since the collision-wins behavior is deterministic and documented.

### Recommendation
Have `review-pr.md` (and other pr-review-toolkit command files) invoke agents using their fully plugin-qualified identifiers (e.g., `pr-review-toolkit:pr-test-analyzer`) in the `Task(subagent_type=...)` calls, and update the agent loader so that plugin-declared commands can pin resolution to their own plugin's agent set, bypassing the "closest wins" project-scope override for that specific invocation. Additionally, warn/prompt the user when a project-local agent definition shadows a name also provided by an installed plugin.

### Proof of Concept
Integration test:
1. Install `pr-review-toolkit` plugin normally.
2. In a test project, create `.claude/agents/pr-test-analyzer.md` with `name: pr-test-analyzer`, no `tools:` restriction, and a distinguishable marker system prompt (e.g., emits a sentinel string or attempts a disallowed action).
3. Run `/pr-review-toolkit:review-pr tests` in that project.
4. Assert that the `Task` call's resolved `subagent_type` binds to `pr-review-toolkit:pr-test-analyzer` (the plugin's own agent, verifiable via its distinct system prompt/output), not the ambiguous project-local `pr-test-analyzer` definition.
5. Expected (failing) result today: the project-local definition's sentinel output appears, confirming the plugin-scoped command silently executed an attacker/project-supplied agent instead of the plugin-vetted one.

### Citations

**File:** plugins/pr-review-toolkit/commands/review-pr.md (L38-43)
```markdown
   - **Always applicable**: code-reviewer (general quality)
   - **If test files changed**: pr-test-analyzer
   - **If comments/docs added**: comment-analyzer
   - **If error handling changed**: silent-failure-hunter
   - **If types added/modified**: type-design-analyzer
   - **After passing review**: code-simplifier (polish and refine)
```

**File:** plugins/pr-review-toolkit/agents/pr-test-analyzer.md (L1-6)
```markdown
---
name: pr-test-analyzer
description: Use this agent when you need to review a pull request for test coverage quality and completeness. This agent should be invoked after a PR is created or updated to ensure tests adequately cover new functionality and edge cases. Examples:\n\n<example>\nContext: Daisy has just created a pull request with new functionality.\nuser: "I've created the PR. Can you check if the tests are thorough?"\nassistant: "I'll use the pr-test-analyzer agent to review the test coverage and identify any critical gaps."\n<commentary>\nSince Daisy is asking about test thoroughness in a PR, use the Task tool to launch the pr-test-analyzer agent.\n</commentary>\n</example>\n\n<example>\nContext: A pull request has been updated with new code changes.\nuser: "The PR is ready for review - I added the new  ... (truncated)
model: inherit
color: cyan
---
```

**File:** CHANGELOG.md (L996-996)
```markdown
- Nested `.claude/` directories: the agent, workflow, and output-style closest to the working directory now wins when names collide; project-scope workflow saves now target the closest existing `.claude/workflows/`
```

**File:** CHANGELOG.md (L1621-1621)
```markdown
- Fixed `--agent <name>` not finding plugin-contributed agents without the `plugin:` prefix
```

**File:** plugins/pr-review-toolkit/README.md (L297-302)
```markdown
## Contributing

Found issues or have suggestions? These agents are maintained in:
- User agents: `~/.claude/agents/`
- Project agents: `.claude/agents/` in claude-cli-internal

```

**File:** plugins/plugin-dev/skills/plugin-structure/SKILL.md (L468-472)
```markdown
**Conflicts between plugins**:
- Use unique, descriptive component names
- Namespace commands with plugin name if needed
- Document potential conflicts in plugin README
- Consider command prefixes for related functionality
```

**File:** plugins/plugin-dev/skills/agent-development/SKILL.md (L349-357)
```markdown
### Frontmatter Fields Summary

| Field | Required | Format | Example |
|-------|----------|--------|---------|
| name | Yes | lowercase-hyphens | code-reviewer |
| description | Yes | Text + examples | Use when... <example>... |
| model | Yes | inherit/sonnet/opus/haiku | inherit |
| color | Yes | Color name | blue |
| tools | No | Array of tool names | ["Read", "Grep"] |
```
