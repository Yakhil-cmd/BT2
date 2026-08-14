### Title
Security-review hook bypass via git operations that don't literally match `Bash(git commit:*)` / `Bash(git push:*)` — analogous to bypassing `compound()`'s fee/reward accounting by calling `claim()` directly - (File: plugins/security-guidance/hooks/hooks.json)

### Summary
The `security-guidance` plugin's automated vulnerability-detection logic ("compound"-equivalent enforcement step) is wired to fire only when the `PostToolUse` hook's `if` string-prefix matcher (`Bash(git commit:*)` / `Bash(git push:*)`) matches the literal Bash `command` field. Any git commit/push performed through a path that doesn't literally match this string pattern skips the review entirely, exactly mirroring how `PirexRewards.claim()` in the original report bypassed `AutoPxGlp.compound()`'s fee/reward logic because the only trigger point for that logic was the `compound()` entry path.

### Finding Description
The plugin's declared trust boundary is: "every git commit and push gets scanned for security issues before/soon-after it happens." That guarantee is implemented as a single, narrow trigger: [1](#0-0) 

The `if` field is a static prefix matcher against the raw `tool_input.command` string of the `Bash` tool. The Python handler itself documents that this matcher is the *only* real gate, and that its own internal regex re-check is merely defensive: [2](#0-1) 

Just like `AutoPxGlp.compound()` in the referenced report, where the *only* code path that calculates protocol fees and updates the `pxGmx` reward accrual is inside `compound()`, gated exclusively on rewards observed as a delta around the `claim()` call performed *by that same function* — here the *only* code path that reviews a commit/push for vulnerabilities is gated exclusively on the literal string `git commit` / `git push` appearing at the start of a `Bash` tool invocation. There is no state-based detection (e.g., "has HEAD advanced since the last reviewed SHA regardless of how") comparable to the recommended mitigation in the original report ("track previous balance ... detect transfers that happened without calling compound()").

Consequently, any commit/push that lands via a route not textually recognized by the `if` matcher — for example:
- A Bash command that performs the commit but doesn't start with `git commit`/`git push` literally (e.g., a shell alias, a wrapper script, `make commit`, `npm run release`, `sh -c 'git commit ...'` invoked through an intermediate binary, or a compound command where the literal prefix is obscured)
- Any non-`Bash` tool capable of running git (an MCP server exposing a "commit" tool, a future native git-integration tool) — the hook is scoped with `"matcher": "Bash"`, so no other tool name reaches this handler at all [3](#0-2) 

will silently skip the security review — the model's actions are never fed through `analyze_code_security`/`agentic_review`, and no `asyncRewake` findings are ever surfaced to the user or the model.

### Impact Explanation
This breaks the plugin's core safety guarantee ("git-diff-based LLM review on stop" and on commit/push, per its own description) for any commit/push path that isn't literally prefixed with `git commit`/`git push` in a `Bash` tool call, or that doesn't go through the `Bash` tool at all. Vulnerable or malicious code (e.g., secrets, backdoors, unsafe patterns introduced by a prompt-injected or compromised agent turn) can be committed and pushed to the user's remote without the compensating security-review control ever firing — a direct analog to the fee/reward loss in the original report, where value that should have been captured by the enforcement logic bypassed it entirely due to an alternate entry path. Note that the `Stop` hook (`handle_stop_hook`) still provides some backstop coverage for the *turn-level* diff, so the practical impact is scoped to git actions that fall outside both (a) the commit/push `if` matcher and (b) whatever diff the Stop hook's baseline-SHA comparison happens to capture (e.g., cross-repo commits via `cd ../other && git commit`, which the code explicitly calls out as a known edge case it tries, imperfectly, to detect via reflog heuristics).

### Likelihood Explanation
Moderate. Achieving the bypass does not require any special privilege beyond what an unprivileged agent turn already has (running `Bash` commands or, if configured, MCP tools). It requires only that the actual git command differ textually from the fixed prefixes `git commit` / `git push` (e.g., via an alias, wrapper, or subshell) or run through a non-Bash surface, both of which are realistic given how flexible git invocation is. The authors' own comments acknowledge multiple such edge cases already found empirically (cross-repo commits, quoted/redirected output, compound commands), indicating the detection surface is inherently incomplete by design rather than by oversight in a single line.

### Recommendation
Do not rely solely on a static string-prefix match against the `Bash` tool's `command` field as the sole gate for triggering the security review. Instead, detect the underlying git state change directly and idempotently, similar to the original report's recommendation to track balances rather than relying on the caller announcing a transfer:
- After every tool call (or on a lightweight periodic/idle check), compare current `HEAD`/reflog state against the last-reviewed SHA recorded in `.git/sg-reviewed-shas`, independent of which tool or command string produced the new commit.
- Broaden the `PostToolUse` matcher beyond `"Bash"` to include any tool capable of executing git (MCP tools, custom plugin tools), or better, decouple the review trigger entirely from `tool_name`/`if` prefix matching and drive it off repository-state diffing.
- Keep the existing `if` matchers only as a fast-path optimization for immediate `asyncRewake` UX, but make the state-diff-based check (already partially present via `_git_reflog_recent_commits`) the authoritative fallback for every hook event, not just the defensive path inside `handle_commit_review_posttooluse`.

### Proof of Concept
1. An agent turn is unrelated to the human-reviewed workflow, and instead of running `git commit -m "..."` directly in `Bash`, it runs the commit through an indirect path that doesn't literally start with `git commit`/`git push`, e.g.:
   - `Bash` command: `alias gc='git commit'; gc -m "add backdoor"` or `make release` (a Makefile target that internally shells out to `git commit && git push`), or `sh -c "git commit -m x && git push"` executed via a wrapper binary shipped by a plugin (`plugins/*/bin/*` executables are explicitly supported per the changelog entry noting "Plugins can now ship executables under `bin/` and invoke them as bare commands from the Bash tool").
2. Because the `hooks.json` `if` string is a literal prefix match on `Bash(git commit:*)` / `Bash(git push:*)`, none of these commands match, so `security_reminder_hook.py`'s `PostToolUse[Bash]` handler is never invoked for this call.
3. The commit is created and pushed to the remote with no `analyze_code_security`/`agentic_review` pass ever running against the introduced diff, and no `asyncRewake` findings are surfaced — identical in effect to the original report's outcome where reward/fee accounting silently never ran because the value transfer occurred outside the sole code path (`compound()`) instrumented to detect it.

*Caveat:* I was not able to execute this end-to-end in a live Claude Code session (no filesystem/terminal access in this analysis mode) to confirm CC's own internal command-prefix parser doesn't already normalize aliases/wrappers before evaluating the `if` string; the CHANGELOG does reference ongoing hardening of "bash command prefix extraction" (e.g., handling `git -C /path log`), so some near-miss forms may already be covered while others (aliases, Makefiles, non-Bash tool paths) remain plausible gaps based on the code's own documented defensive comments.

### Citations

**File:** plugins/security-guidance/hooks/hooks.json (L35-55)
```json
      {
        "hooks": [
          {
            "type": "command",
            "command": "bash \"${CLAUDE_PLUGIN_ROOT}/hooks/sg-python.sh\" \"${CLAUDE_PLUGIN_ROOT}/hooks/security_reminder_hook.py\"",
            "if": "Bash(git commit:*)",
            "asyncRewake": true,
            "rewakeMessage": "Background security review of commit — address or acknowledge the findings below, then continue with the user's original request or continue waiting for their reply:",
            "rewakeSummary": "Commit security review found issues"
          },
          {
            "type": "command",
            "command": "bash \"${CLAUDE_PLUGIN_ROOT}/hooks/sg-python.sh\" \"${CLAUDE_PLUGIN_ROOT}/hooks/security_reminder_hook.py\"",
            "if": "Bash(git push:*)",
            "asyncRewake": true,
            "rewakeMessage": "Background security review of pushed commits not yet reviewed — address or acknowledge the findings below, then continue with the user's original request or continue waiting for their reply:",
            "rewakeSummary": "Push security review found issues"
          }
        ],
        "matcher": "Bash"
      }
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L916-921)
```python
    command = tool_input.get("command", "")
    if not isinstance(command, str) or not _GIT_COMMIT_RE.search(command):
        # Defensive only — hooks.json's `"if": "Bash(git commit:*)"` is the
        # real gate so CC never spawns python3 for ls/grep/etc. This catches
        # cases where CC's command matching fails open and spawns the hook anyway.
        sys.exit(0)
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L2095-2098)
```python
    if tool_name == "Bash" and hook_event_name == "PostToolUse":
        cmd = (input_data.get("tool_input") or {}).get("command", "") or ""
        if not (_GIT_COMMIT_RE.search(cmd) or _GIT_PUSH_RE.search(cmd)):
            return
```
