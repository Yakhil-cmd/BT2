### Title
Unrestricted `Bash` grant in `review-pr` command frontmatter enables prompt-injection-driven command execution without approval - ([File: plugins/pr-review-toolkit/commands/review-pr.md])

### Summary
The `review-pr` slash command declares `allowed-tools: ["Bash", "Glob", "Grep", "Read", "Task"]` with no command filter on `Bash`, pre-authorizing the LLM to run *any* shell command for the duration of the command without per-invocation user approval. Because the command's own workflow instructs the agent to pull in untrusted content (PR diff, `gh pr view` output, changed-file contents) before deciding what to do, an attacker who controls a reviewed PR's diff/description can inject instructions that the agent will execute via the already-approved, unscoped `Bash` tool.

### Finding Description
The frontmatter is: [1](#0-0) 

and the workflow explicitly has the agent ingest untrusted, attacker-influenced repository/PR data before further action: [2](#0-1) 

The user-supplied `$ARGUMENTS` is also interpolated verbatim into the prompt with no sanitization: [3](#0-2) 

The repository's own plugin-development documentation states that bare `Bash` (without a `(cmd:*)` filter) is an explicit anti-pattern that should be rejected/fixed, and that it should always be scoped, e.g. `Bash(git:*)`: [4](#0-3) [5](#0-4) 

`review-pr.md` violates this documented invariant by granting `Bash` unscoped. Because `allowed-tools` pre-authorizes tool use for the session (bypassing the normal per-command approval prompt for tools/patterns that match the list), any `Bash` invocation the agent makes while running `/pr-review-toolkit:review-pr` is auto-approved, regardless of what command it decides to run. The workflow directs the agent to read `git diff`, PR file contents, and `gh pr view` output — all of which are attacker-controllable if the reviewed PR is opened by an untrusted contributor (a normal, unprivileged repository interaction). If that content contains a prompt-injection payload (e.g. a code comment, commit message, or PR description instructing the model to run a specific shell command "as part of the review"), the model can act on it and execute it via `Bash` without any additional user confirmation, since the tool is already blanket-approved by the command's own frontmatter.

This matches the exact bug class Anthropic has fixed before in Claude Code core (confirming it is bounty-relevant): "Fixed a Bash tool permission bypass where a backslash-escaped flag could be auto-allowed as read-only and lead to arbitrary code execution" and "Fixed compound Bash commands bypassing forced permission prompts for safety checks and explicit ask rules." [6](#0-5) 

### Impact Explanation
An unprivileged attacker who can open a PR/branch reviewed with this command can achieve arbitrary command execution on the reviewer's machine without any approval prompt, because the command's frontmatter pre-grants unrestricted `Bash` for the whole session. This is a direct approval-bypass / unauthorized-command-execution path reachable purely from ordinary PR content, matching Claude Code's "permission bypass leading to arbitrary code execution" bounty category.

### Likelihood Explanation
Preconditions: a user must run `/pr-review-toolkit:review-pr` (or an equivalent parallel-agent invocation) against a PR/branch containing attacker-controlled diff/description content, and the underlying model must be susceptible to acting on injected instructions embedded in that content (a well-established Claude Code prompt-injection risk area, as acknowledged by the repo's own `security-guidance` hook, which explicitly calls out "unrestricted Bash/shell tool" grants for LLM subprocesses as unsafe unless sandboxed or a strong allow/deny classifier is present) [7](#0-6) . No maintainer privilege, leaked keys, or social engineering is required — only that the victim runs this specific bundled command on an attacker-supplied PR, which is the command's stated primary use case.

### Recommendation
Scope the `Bash` entry in `review-pr.md`'s `allowed-tools` to the minimal set of concrete command prefixes actually needed (e.g. `Bash(git diff:*)`, `Bash(git status:*)`, `Bash(gh pr view:*)`), following the pattern documented elsewhere in this same repository, instead of granting unscoped `Bash`. Additionally, treat all PR/diff/`gh` output ingested by the workflow as untrusted data rather than instructions, and avoid letting the agent freely choose additional Bash invocations based on that content.

### Proof of Concept
Integration test plan:
1. Create a test PR branch containing a file whose diff/comment contains a prompt-injection payload instructing the agent to run a benign-but-detectable command, e.g. `touch /tmp/pwned` or `curl http://attacker.test/marker`.
2. Invoke `/pr-review-toolkit:review-pr` against this PR in a Claude Code session configured with the plugin's default `allowed-tools`.
3. Assert that the agent invokes `Bash` with the injected command **without** any permission prompt being shown to the user (compare against a control run where `allowed-tools` is scoped to `Bash(git diff:*)` only, where the same injected command should be blocked/prompted).
4. Expected assertion: with unscoped `Bash`, `/tmp/pwned` is created (or the network callback is observed) with zero approval prompts; with scoped `Bash(git diff:*)`, the injected command is rejected or requires explicit user approval.

### Citations

**File:** plugins/pr-review-toolkit/commands/review-pr.md (L1-5)
```markdown
---
description: "Comprehensive PR review using specialized agents"
argument-hint: "[review-aspects]"
allowed-tools: ["Bash", "Glob", "Grep", "Read", "Task"]
---
```

**File:** plugins/pr-review-toolkit/commands/review-pr.md (L11-11)
```markdown
**Review Aspects (optional):** "$ARGUMENTS"
```

**File:** plugins/pr-review-toolkit/commands/review-pr.md (L30-34)
```markdown
3. **Identify Changed Files**
   - Run `git diff --name-only` to see modified files
   - Check if PR already exists: `gh pr view`
   - Identify file types and what reviews apply

```

**File:** plugins/plugin-dev/skills/command-development/references/frontmatter-reference.md (L124-128)
```markdown
**Best practices:**
- Be as restrictive as possible
- Use command filters for Bash (e.g., `git:*` not `*`)
- Only specify when different from conversation permissions
- Document why specific tools are needed
```

**File:** plugins/plugin-dev/skills/command-development/references/frontmatter-reference.md (L431-436)
```markdown
**Incorrect tool specification:**
```yaml
allowed-tools: Bash  # ❌ Missing command filter
```

**Fix:** Use `Bash(git:*)` format
```

**File:** CHANGELOG.md (L2524-2525)
```markdown
- Fixed a Bash tool permission bypass where a backslash-escaped flag could be auto-allowed as read-only and lead to arbitrary code execution
- Fixed compound Bash commands bypassing forced permission prompts for safety checks and explicit ask rules in auto and bypass-permissions modes
```

**File:** plugins/security-guidance/hooks/llm.py (L846-846)
```python
**Agent/Subprocess Permission Bypass**: Code that spawns Claude Code, a subagent, or any LLM-with-tools subprocess with permission gates removed — `--permission-mode bypassPermissions`, `--dangerously-skip-permissions`, or an unrestricted Bash/shell tool. Allowing Claude to execute arbitrary bash is only safe when the process runs inside an isolation boundary such as a sandbox OR every command passes through a strong allow/deny command classifier; if neither is in the diff, flag it.
```
