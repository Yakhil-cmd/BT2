### Title
Unbounded, uncached file read of untrusted `.claude/hookify.*.local.md` content causes repeated resource exhaustion in hook pipeline - ([File: plugins/hookify/core/config_loader.py])

### Summary
`load_rule_file` opens and fully reads any file matched by `.claude/hookify.*.local.md` with no size limit, and `load_rules` performs this glob+read+parse cycle from scratch on every single `PreToolUse`/`PostToolUse`/`Stop`/`UserPromptSubmit` hook invocation with no caching. An attacker who can get an oversized or malformed file committed under `.claude/` (e.g. via a merged PR) can force repeated, unbounded memory/CPU consumption on every tool call in a session, degrading or timing out the hookify enforcement hooks. The information-disclosure sub-claim (stderr text reaching `systemMessage`) does not hold, because `load_rule_file` swallows `UnicodeDecodeError`/`IOError`/etc. internally and returns `None`, so the printed stderr text never propagates into the `systemMessage` built by the hook wrapper scripts.

### Finding Description
`load_rule_file` reads the entire file unconditionally: [1](#0-0) . There is no file-size check, streaming limit, or timeout guard before `f.read()`. `load_rules` globs `.claude/hookify.*.local.md` and calls `load_rule_file` for every match, with no result caching between calls: [2](#0-1) . Because `load_rules` is invoked fresh on every hook event by `pretooluse.py`, `posttooluse.py`, `stop.py`, and `userpromptsubmit.py` [3](#0-2) , an oversized file under `.claude/` is re-read and re-parsed on every single tool invocation in the session, not just once.

Regarding the information-disclosure claim: `load_rule_file` catches `UnicodeDecodeError` and all other exceptions internally and returns `None` rather than raising [4](#0-3) . The `print(..., file=sys.stderr)` calls in both `load_rule_file` and `load_rules` never reach the hook script's own `except Exception` block that constructs `systemMessage` [5](#0-4) , since that outer handler only fires for exceptions that escape `load_rules`/`evaluate_rules`, and `load_rule_file`/`load_rules` do not let file-read exceptions escape. Therefore stderr content is not relayed into `systemMessage` or otherwise exposed to the model/user; the info-disclosure channel described in the question is not actually reachable.

### Impact Explanation
The realistic, exploitable impact is denial-of-service against hookify's own guard-rule enforcement: an oversized/malformed `.claude/hookify.*.local.md` file causes elevated memory/CPU usage and potential timeout on every `PreToolUse`/`PostToolUse`/`Stop`/`UserPromptSubmit` invocation for the entire session (hooks run with a 10s timeout per `hooks.json` and fail open via `sys.exit(0)` in `finally` blocks, so guard rules are effectively disabled for that call rather than blocking the operation). This is a scoped DoS of one plugin's security control, not a broader Claude Code sandbox escape or secret leak.

### Likelihood Explanation
Requires an attacker-controlled file to land under `.claude/` in the working repository (e.g., via a merged/checked-out PR branch) — a plausible but non-trivial precondition since it requires some write path into the repo. Once present, the trigger is automatic and repeatable: any subsequent tool call in a Claude Code session using hookify will re-read the file.

### Recommendation
Add a file-size cap (e.g., stat the file and skip/log-only if it exceeds a few hundred KB) before reading in `load_rule_file`, and cache parsed rules keyed by file path + mtime in `load_rules` to avoid re-reading unchanged files on every hook invocation.

### Proof of Concept
Unit/fuzz test: create a `.claude/hookify.big.local.md` file of several hundred MB (or a crafted file with invalid UTF-8 bytes), call `load_rules()` repeatedly in a loop simulating multiple hook invocations, and assert (a) wall-clock time per call stays bounded (e.g. under a defined threshold) and (b) memory usage does not scale with repeated calls (i.e., caching/size-limiting is applied). Separately assert that no stderr content produced by `load_rule_file` ever appears in the `systemMessage` returned by `pretooluse.py`/`posttooluse.py`/etc., confirming the info-disclosure path is not present.

### Citations

**File:** plugins/hookify/core/config_loader.py (L209-216)
```python
    # Find all hookify.*.local.md files
    pattern = os.path.join('.claude', 'hookify.*.local.md')
    files = glob.glob(pattern)

    for file_path in files:
        try:
            rule = load_rule_file(file_path)
            if not rule:
```

**File:** plugins/hookify/core/config_loader.py (L250-252)
```python
    try:
        with open(file_path, 'r') as f:
            content = f.read()
```

**File:** plugins/hookify/core/config_loader.py (L263-275)
```python
    except (IOError, OSError, PermissionError) as e:
        print(f"Error: Cannot read {file_path}: {e}", file=sys.stderr)
        return None
    except (ValueError, KeyError, AttributeError, TypeError) as e:
        print(f"Error: Malformed rule file {file_path}: {e}", file=sys.stderr)
        return None
    except UnicodeDecodeError as e:
        print(f"Error: Invalid encoding in {file_path}: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error: Unexpected error parsing {file_path} ({type(e).__name__}): {e}", file=sys.stderr)
        return None

```

**File:** plugins/hookify/hooks/pretooluse.py (L35-52)
```python
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

**File:** plugins/hookify/hooks/pretooluse.py (L61-66)
```python
    except Exception as e:
        # On any error, allow the operation and log
        error_output = {
            "systemMessage": f"Hookify error: {str(e)}"
        }
        print(json.dumps(error_output), file=sys.stdout)
```
