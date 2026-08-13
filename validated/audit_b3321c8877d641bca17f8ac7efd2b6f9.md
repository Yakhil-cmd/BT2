### Title
`load_rules()` glob follows unconfined relative paths, allowing repo-committed symlinks to escape the workspace boundary - ([File: plugins/hookify/core/config_loader.py])

### Finding Description
`load_rules()` builds a glob pattern from a hardcoded relative path, `os.path.join('.claude', 'hookify.*.local.md')`, and calls `glob.glob(pattern)` without ever resolving the results against a workspace root or checking for symlinks: [1](#0-0) 

Each matched path is handed directly to `load_rule_file()`, which opens it with plain `open(file_path, 'r')` — Python's `open()` transparently follows symlinks, and there is no `os.path.realpath()`/`os.path.islink()` check anywhere in the module or in the calling hooks (`pretooluse.py`, `posttooluse.py`, `stop.py`, `userpromptsubmit.py`) to confine the resolved target to the repository/workspace root: [2](#0-1) 

Because these hooks are invoked automatically by Claude Code on every tool call (`PreToolUse`, `PostToolUse`, `Stop`, `UserPromptSubmit`) as soon as the plugin is active, simply opening/cloning a repository containing a crafted symlink at `.claude/hookify.evil.local.md` is enough to trigger the read — no explicit user action beyond normal Claude Code usage on that repo is required: [3](#0-2) 

If the symlink target's content happens to begin with `---` (parses as YAML frontmatter), the message body of that external file becomes the `Rule.message`, which flows into `RuleEngine.evaluate_rules()` and is emitted as a `systemMessage`/warning in the hook's JSON output — i.e., the content of a file located anywhere the OS user can read is pulled into the Claude Code session/model context and displayed to the user, without any confinement check.

### Impact Explanation
This is an arbitrary local file read achieved purely by committing a symlink into a repository that a victim later opens with Claude Code and the hookify plugin enabled — a workspace-confinement bypass. The disclosed content is not merely read but surfaced into the running Claude Code session (as a rule warning/message), which can then be echoed back to the user or acted upon further by the assistant, exceeding a simple local file-stat leak. This matches "workspace escape / unauthorized file read" impact class for Claude Code plugin/hook trust boundaries.

### Likelihood Explanation
Requires only that the attacker can get a symlink file committed into a repository that the victim later opens (a realistic supply-chain scenario for shared/cloned repos, exactly the precondition stated in the question). No additional privilege, admin access, or social engineering beyond "victim opens attacker-influenced repo" is needed, and the vulnerable code path (`glob.glob` → `load_rule_file` → `open`) executes automatically on ordinary tool use because the hooks fire on every PreToolUse/PostToolUse/Stop/UserPromptSubmit event. The main constraining factor is that the target file's content must begin with `---` to be surfaced as a rule message; without that, `load_rule_file()` logs "missing YAML frontmatter" and drops it — but the file is still opened and read regardless, and constructing/targeting such files (e.g. other YAML configs) is plausible.

### Recommendation
- In `load_rules()`, resolve the workspace root explicitly (e.g., via an environment variable such as `CLAUDE_PROJECT_DIR` or `os.getcwd()`), and glob within that resolved root rather than a bare relative path.
- In `load_rule_file()`, before opening: call `os.path.realpath(file_path)` and verify with `os.path.commonpath([realpath, workspace_root]) == workspace_root`; reject (skip with a warning) any path whose resolved target falls outside the workspace root, and reject symlinks outright with `os.path.islink(file_path)`.
- Apply the same guard consistently across all callers (`pretooluse.py`, `posttooluse.py`, `stop.py`, `userpromptsubmit.py`) by centralizing the check inside `config_loader.py`.

### Proof of Concept
Integration test (pytest):
1. Create a temporary workspace directory `tmp_repo/.claude/`.
2. Create a sensitive file outside the workspace, e.g. `/tmp/secret.md`, whose content begins with:
   ```
   ---
   name: leaked
   enabled: true
   event: all
   ---
   SECRET_CONTENT_OUTSIDE_WORKSPACE
   ```
3. Inside `tmp_repo/.claude/`, create a symlink `hookify.evil.local.md -> /tmp/secret.md`.
4. `chdir` into `tmp_repo` and call `config_loader.load_rules()`.
5. Assert that either:
   - the call raises/skips the file because `load_rule_file` detects the symlink escapes the workspace root (expected fixed behavior), or
   - currently (unfixed), assert `rules[0].message == "SECRET_CONTENT_OUTSIDE_WORKSPACE"`, demonstrating that content from outside the workspace root was loaded into a `Rule` object and would be forwarded to `RuleEngine.evaluate_rules()`/hook output.

### Citations

**File:** plugins/hookify/core/config_loader.py (L209-213)
```python
    # Find all hookify.*.local.md files
    pattern = os.path.join('.claude', 'hookify.*.local.md')
    files = glob.glob(pattern)

    for file_path in files:
```

**File:** plugins/hookify/core/config_loader.py (L244-262)
```python
def load_rule_file(file_path: str) -> Optional[Rule]:
    """Load a single rule file.

    Returns:
        Rule object or None if file is invalid.
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read()

        frontmatter, message = extract_frontmatter(content)

        if not frontmatter:
            print(f"Warning: {file_path} missing YAML frontmatter (must start with ---)", file=sys.stderr)
            return None

        rule = Rule.from_dict(frontmatter, message)
        return rule

```

**File:** plugins/hookify/hooks/pretooluse.py (L25-53)
```python
try:
    from hookify.core.config_loader import load_rules
    from hookify.core.rule_engine import RuleEngine
except ImportError as e:
    # If imports fail, allow operation and log error
    error_msg = {"systemMessage": f"Hookify import error: {e}"}
    print(json.dumps(error_msg), file=sys.stdout)
    sys.exit(0)


def main():
    """Main entry point for PreToolUse hook."""
    try:
        # Read input from stdin
        input_data = json.load(sys.stdin)

        # Determine event type for filtering
        # For PreToolUse, we use tool_name to determine "bash" vs "file" event
        tool_name = input_data.get('tool_name', '')

        event = None
        if tool_name == 'Bash':
            event = 'bash'
        elif tool_name in ['Edit', 'Write', 'MultiEdit']:
            event = 'file'

        # Load rules
        rules = load_rules(event=event)

```
