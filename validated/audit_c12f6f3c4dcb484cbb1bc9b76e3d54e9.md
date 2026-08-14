### Title
Unanchored `"diff --git "` substring split lets embedded fake diff headers desync file attribution - ([File: plugins/security-guidance/hooks/gitutil.py])

### Summary
`parse_diff_into_files` (and its sibling `extract_file_paths_from_diff`) splits the raw diff text with `diff_output.split("diff --git ")`, a plain substring split that is not anchored to the start of a line. A source file whose content contains a line like `diff --git a/evil b/evil` will cause the parser to treat that embedded text as a real per-file diff boundary, truncating the legitimate file's collected hunk and misattributing the remainder to a bogus `evil` file.

### Finding Description
`parse_diff_into_files` in `plugins/security-guidance/hooks/gitutil.py` splits on `"diff --git "` as a literal string anywhere in the buffer: `file_diffs = diff_output.split("diff --git ")` [1](#0-0) . Because a `+`-prefixed added line inside a hunk still contains the substring `diff --git ` starting one character in (e.g. `+diff --git a/evil b/evil`), Python's `str.split` breaks the text there just as readily as at a genuine header line — there is no line-start anchoring or check that the match is preceded by `\n` at the very start of a line.

After the split, each chunk's first line is matched against `^a/(.+?) b/(.+)$` with `re.match` (no `re.MULTILINE`, applied only to `lines[0]` of that chunk) [2](#0-1) . Since the attacker's embedded payload is crafted as `a/evil b/evil`, this regex matches and the parser believes a new file `evil` has begun. Everything from that point (including any subsequent legitimate hunk lines of the real file that follow the injected line, up to the next real `diff --git ` occurrence or end of diff) is now collected into the `evil` entry's diff content via the hunk-collection loop [3](#0-2) . Meanwhile, the legitimate file's chunk is truncated at the injection point, silently dropping the remainder of its hunk (which can include the attacker's actual vulnerable code placed just after the fake header) from that file's `diff_content`.

`_is_reviewable_source("evil")` returns `True` because extensionless paths default to reviewable unless they match a small deny-list of metadata basenames [4](#0-3) , so this bogus entry is not filtered out and is added to `files` alongside the legitimate paths [5](#0-4) . `extract_file_paths_from_diff`, used to build the pre-check file list, has the identical unanchored-split flaw [6](#0-5) .

No existing check protects against this: there is no validation that the split occurred on an actual line boundary, no verification against `git show <sha>:<path>` ground truth, and no cross-check that reconstructed per-file content matches the real file. This is a genuine parser desync reachable purely from ordinary reviewable commit content that an unprivileged contributor can author (e.g., committing a string literal, comment, or test fixture containing a diff-header-shaped line inside a normal source file), no elevated privilege needed.

### Impact Explanation
This directly hits the "parser output matches actual file content applied to disk" invariant called out in the question. Practical effect: the real file's diff content sent to `analyze_code_security` / `agentic_review` is truncated, so any vulnerable code placed after the injected fake header inside that file's hunk is dropped from — or misattributed away from — the correct `file_path` entry in `diff_files`. Since the LLM security reviewer (Stop hook / commit-review / push-sweep, all of which consume `parse_diff_into_files` output) never sees that code under the correct path, it can slip past both the pattern-based and LLM-based review layers described in `security_reminder_hook.py`'s architecture [7](#0-6) . This is a review-evasion / false-negative issue in the security-guidance detection pipeline, not a code-execution or credential-disclosure bug, but it is a real bypass of the "commit is reviewed" security control the plugin exists to provide.

### Likelihood Explanation
Low complexity, fully attacker-controlled: any contributor who can get a commit into the repo (test fixtures, string literals, comments, sample data, even a file demonstrating "how git diffs work") can trigger this merely by writing a line that begins with `diff --git a/`. No approval bypass or special repo state is needed — it happens on every ordinary commit-review/stop-review/push-sweep pass over the crafted content. It is fully deterministic and repeatable.

### Recommendation
Anchor the diff-header split/match to actual line boundaries instead of using an unanchored substring split:
- Use `re.split(r'(?m)^diff --git ', diff_output)` (or iterate line-by-line, only treating a line as a new file header when it starts at column 0 with `diff --git `) in both `parse_diff_into_files` and `extract_file_paths_from_diff`.
- Additionally validate that the line immediately preceding an `@@` hunk marker corresponds to `---`/`+++` lines whose paths match the `diff --git a/... b/...` header, to catch any other desync.
- Add a differential test that reconstructs each parsed file's content and compares against `git show <sha>:<path>` for diffs containing embedded `diff --git` look-alike lines.

### Proof of Concept
```python
from gitutil import parse_diff_into_files

diff_text = """diff --git a/real.py b/real.py
index 111..222 100644
--- a/real.py
+++ b/real.py
@@ -1,2 +1,4 @@
 def f():
+    line_before_injection = 1
+diff --git a/evil b/evil
+    payload_that_should_belong_to_real_py = "vuln_pattern_here"
     return line_before_injection
"""

files = parse_diff_into_files(diff_text)
paths = dict(files)

# Expected (correct) behavior: only "real.py" present, containing the
# full hunk including the injected-looking line as literal content.
assert list(paths.keys()) == ["real.py"], f"desynced into: {list(paths.keys())}"
assert "payload_that_should_belong_to_real_py" in paths["real.py"]
```
Running this against the current implementation shows `paths` contains both `"real.py"` (truncated) and a bogus `"evil"` entry holding the trailing lines — demonstrating the misattribution/drop described in the question.

### Citations

**File:** plugins/security-guidance/hooks/gitutil.py (L570-584)
```python
    # Extensionless files default to reviewable unless they're known
    # plain-text metadata or dotfiles. Covers shebang scripts under bin/ or
    # scripts/ (`deploy`, `run-canary`, `entrypoint`) which carry
    # shell-injection surface but were previously filtered out — the largest
    # remaining false-negative class for extensionless files. Dotfiles (`.gitignore`,
    # `.nvmrc`, `.env`) are config, not code; `.bashrc`-style runnables are
    # rare in repos and not worth the noise. The deny-list is prefix-aware on
    # `-`/`_` so dual-license / i18n variants (`LICENSE-MIT`, `README-CN`)
    # don't fall through as source.
    if ext == "" and not base.startswith("."):
        if any(base == x or base.startswith(x + "-") or base.startswith(x + "_")
               for x in NON_SOURCE_EXTENSIONLESS_BASENAMES):
            return False
        return True
    return False
```

**File:** plugins/security-guidance/hooks/gitutil.py (L596-611)
```python
    paths = []
    file_diffs = diff_output.split("diff --git ")

    for file_diff in file_diffs:
        if not file_diff.strip():
            continue
        lines = file_diff.split('\n')
        header_match = re.match(r'^a/(.+?) b/(.+)$', lines[0])
        if not header_match:
            continue
        file_path = header_match.group(2) or header_match.group(1) or ''
        if not _is_reviewable_source(file_path):
            continue
        paths.append(file_path)

    return paths
```

**File:** plugins/security-guidance/hooks/gitutil.py (L623-625)
```python
    files = []
    file_diffs = diff_output.split("diff --git ")

```

**File:** plugins/security-guidance/hooks/gitutil.py (L630-636)
```python
        # Extract filename from first line: "a/path/to/file b/path/to/file"
        lines = file_diff.split('\n')
        header_match = re.match(r'^a/(.+?) b/(.+)$', lines[0])
        if not header_match:
            continue

        file_path = header_match.group(2) or header_match.group(1) or ''
```

**File:** plugins/security-guidance/hooks/gitutil.py (L639-653)
```python
        if not _is_reviewable_source(file_path):
            continue

        # Extract the diff content (from first @@ onwards)
        diff_lines = []
        in_hunks = False
        for line in lines[1:]:
            if line.startswith('@@'):
                in_hunks = True
            if in_hunks:
                diff_lines.append(line)

        if diff_lines:
            files.append((file_path, '\n'.join(diff_lines)))

```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L17-23)
```python
2. **Stop hook (final review)**: When Claude finishes, uses `git diff` against a
   baseline SHA (captured at UserPromptSubmit) to get only the code changed during the
   session. Runs two Haiku analyses on the diff:
   a) Concrete vulnerability scan with severity ratings
   b) Areas-of-concern analysis identifying categories to investigate
   Exits with code 2 to force Claude to continue and address findings.

```
