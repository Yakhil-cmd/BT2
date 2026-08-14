### Title
Symlink-based path traversal in hookify rule discovery leaks arbitrary file contents outside `.claude/` - ([File: plugins/hookify/core/config_loader.py])

### Summary
`load_rules()` builds the glob pattern `.claude/hookify.*.local.md` and passes matched paths directly to `open()` without verifying that the resolved (post-symlink) path stays inside the project's `.claude` directory. A repository checkout containing a symlink such as `.claude/hookify.evil.local.md -> /some/sensitive/file` will be matched by `glob.glob` and its target's contents will be read and, when accessed through the `/hookify:list` or `/hookify:configure` slash commands (which reuse the identical glob pattern with the generic `Read` tool), surfaced directly into the model's context/chat.

### Finding Description
`load_rules()` computes `pattern = os.path.join('.claude', 'hookify.*.local.md')` and calls `glob.glob(pattern)` [1](#0-0) . Neither `glob.glob` nor the subsequent code checks whether a returned entry is a symlink or whether `os.path.realpath(file_path)` still resolves under `.claude/`. `load_rule_file()` then opens the path directly: `with open(file_path, 'r') as f: content = f.read()` [2](#0-1) . Python's `open()` follows symlinks by default, so if the checked-out repo contains a symlink named `.claude/hookify.symlink.local.md` pointing to a file outside the intended `.claude` scope (e.g. `~/.ssh/id_rsa`, another project's `.env`, or any file readable by the OS user running Claude Code), its content is read into the process.

This same unguarded glob pattern is reused verbatim by the `/hookify:list` and `/hookify:configure` slash-command workflows, which instruct the model to run the `Glob` tool with pattern `.claude/hookify.*.local.md` and then use the generic `Read` tool on every match [3](#0-2) [4](#0-3) . Because `Read`/`Glob` operate at the OS file level, they follow the same symlink and place the target file's raw content into the model's context, which the workflow then displays back to the user (rule preview, table, etc.). Unlike `load_rules()` used by the hooks (which additionally requires the target to contain valid `---` YAML frontmatter before surfacing a `Rule`), the slash-command path has no such structural requirement — the `Read` tool will display whatever bytes the symlink resolves to, regardless of format, satisfying the leak even for files that are not markdown/rule-shaped.

No workspace-confinement check exists anywhere in this call chain: `load_rules` → `glob.glob` → `load_rule_file` → `open`, nor in the command definitions that re-glob and `Read` the same pattern.

### Impact Explanation
An attacker who can get a victim to clone/open a crafted repository (a completely ordinary, unprivileged git-checkout scenario) can exfiltrate the contents of arbitrary files readable by the victim's OS user account — such as SSH keys, cloud credentials, or other local secrets — by planting a symlink inside `.claude/` matching the `hookify.*.local.md` glob. The leaked content can end up displayed in the chat transcript via `/hookify:list` or `/hookify:configure`, i.e., disclosed outside the intended reviewed project scope. This matches a workspace-escape / secret-disclosure impact class.

### Likelihood Explanation
Feasibility is high: creating a symlink inside a git repository is a normal, unprivileged git operation (`git add -A` with `core.symlinks` enabled, the default on Linux/macOS), requiring no special permissions on the victim machine beyond a normal checkout. The only user action needed is running `/hookify:list` or `/hookify:configure` (or simply triggering any tool call, since `pretooluse.py`/`posttooluse.py`/`stop.py` also call `load_rules()` on every tool invocation) [5](#0-4) . This makes the bug reliably and repeatably triggerable.

### Recommendation
In `load_rules()`/`load_rule_file()`, resolve each matched path with `os.path.realpath()` and verify it is contained within `os.path.realpath('.claude')` before opening; reject (and log/skip) any entry that is a symlink or whose real path escapes `.claude/`. Apply the same confinement check in the `/hookify:list` and `/hookify:configure` command workflows before invoking `Read` on globbed rule files, or have those commands delegate to a hardened loader function instead of duplicating the raw glob+Read pattern.

### Proof of Concept
Integration test:
1. Create a temporary project directory with a `.claude/` folder.
2. Outside the project root, create a "secret" file with known sensitive content (e.g., `/tmp/secret_outside/id_rsa_fake`).
3. Inside `.claude/`, create a symlink `hookify.symlink.local.md` pointing to the secret file (`os.symlink(secret_path, '.claude/hookify.symlink.local.md')`).
4. Run `config_loader.load_rules()` with CWD set to the project directory.
5. Assert that either: (a) `load_rules()` returns no rule derived from the symlinked file, and the secret file's content is never read/logged, or (b) if the code is patched, assert `os.path.realpath()` check causes the entry to be skipped with a logged warning.
6. Separately, simulate the `/hookify:list` command's `Glob` + `Read` sequence against the same fixture and assert the returned match list excludes symlinked entries escaping `.claude/`, or that the tool refuses to follow them.

### Citations

**File:** plugins/hookify/core/config_loader.py (L209-211)
```python
    # Find all hookify.*.local.md files
    pattern = os.path.join('.claude', 'hookify.*.local.md')
    files = glob.glob(pattern)
```

**File:** plugins/hookify/core/config_loader.py (L250-252)
```python
    try:
        with open(file_path, 'r') as f:
            content = f.read()
```

**File:** plugins/hookify/commands/configure.md (L14-30)
```markdown
### 1. Find Existing Rules

Use Glob tool to find all hookify rule files:
```
pattern: ".claude/hookify.*.local.md"
```

If no rules found, inform user:
```
No hookify rules configured yet. Use `/hookify` to create your first rule.
```

### 2. Read Current State

For each rule file:
- Read the file
- Extract `name` and `enabled` fields from frontmatter
```

**File:** plugins/hookify/commands/list.md (L14-22)
```markdown
1. Use Glob tool to find all hookify rule files:
   ```
   pattern: ".claude/hookify.*.local.md"
   ```

2. For each file found:
   - Use Read tool to read the file
   - Extract frontmatter fields: name, enabled, event, pattern
   - Extract message preview (first 100 chars)
```

**File:** plugins/hookify/hooks/pretooluse.py (L51-52)
```python
        # Load rules
        rules = load_rules(event=event)
```
