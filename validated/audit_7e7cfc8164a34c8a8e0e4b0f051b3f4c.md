### Title
Pathspec-magic injection via colon-prefixed filenames lets attacker-controlled repo content escape `get_git_diff` scoping - (File: `plugins/security-guidance/hooks/gitutil.py`)

### Summary
`get_git_diff` restricts the security-review diff to specific touched files by building a pathspec string via `_diff_pathspec` and passing it after `--` to `git diff`, but the underlying `git` invocation never disables git's pathspec "magic" parsing (`--literal-pathspecs` / `core.literalPathspecs=true`). A repo-controlled file whose repo-relative path begins with `:` is interpreted by git as a pathspec magic signature (e.g. `:(exclude)`, `:(icase)`, `:!`) rather than as a literal filename, letting an attacker who can add such a filename to the working tree change what `git diff` actually scopes to or make the call fail.

### Finding Description
`_diff_pathspec` (`plugins/security-guidance/hooks/gitutil.py:70-88`) computes repo-relative paths from the caller-supplied `paths` and correctly guards against symlink/`..`-based escapes by `os.path.realpath`-resolving both `cwd` and each path and dropping any relpath starting with `..`. That mitigates the symlink-escape variant of this question.

However, the resulting relative-path strings are spliced verbatim into the `git diff … -- <pathspecs>` command in `get_git_diff` (`plugins/security-guidance/hooks/gitutil.py:406-419`), and `GIT_CMD` (`plugins/security-guidance/hooks/gitutil.py:25-29`) only sets `core.fsmonitor=false` and `core.hooksPath=/dev/null` — it never sets `core.literalPathspecs=true` nor passes `--literal-pathspecs`.

Git's pathspec grammar treats any pathspec argument that begins with `:` as a magic signature (`:(glob)`, `:(icase)`, `:(exclude)`/`:!`, `:(attr:…)`, etc.) rather than a literal path, unless literal-pathspec mode is enabled. A repo file whose basename is a top-level path (e.g. a file literally named `:(exclude)foo.py`, or `:!x`) will, after `os.path.relpath`, produce a pathspec string beginning with `:` and be handed to `git diff` unescaped. Depending on the exact string, this either:
- causes `git diff` to exit non‑zero (e.g. an exclude-only pathspec with no positive pattern), so `get_git_diff` returns `None` (`plugins/security-guidance/hooks/gitutil.py:420-422`) instead of the intended targeted diff or the `""` sentinel that the code explicitly documents as meaning "nothing to review, don't do an unrestricted diff" (`plugins/security-guidance/hooks/gitutil.py:407-412`); or
- causes the pathspec to match a different set of files than the single touched file intended (glob/icase/attr expansion), broadening or narrowing the diff outside the caller's intended scope.

Either outcome breaks the stated invariant "git path scoping must never escape the intended repo target": the review call is driven by attacker-controlled filenames that are not what the reviewer intended to scope to, and the file's actual content differs from what the security reviewer receives (or the reviewer receives nothing because the call errors).

### Impact Explanation
This is a security-control bypass: the Stop-hook/commit-review diff collection is the mechanism that gates whether Claude's own edits get scanned for vulnerabilities before being surfaced/allowed. If an attacker can plant (or get Claude to create/touch) a colon-prefixed filename in the working tree, the targeted `git diff` for that turn can silently fail (`None`) or scope to the wrong set of files, letting malicious/vulnerable content pass through the review pipeline unexamined — a silent disable/bypass of the review boundary, matching the "Security-control bypass that silently disables or routes around blocking, review, or permission boundaries" impact class.

### Likelihood Explanation
Preconditions are modest: the attacker only needs the ability to have a file with a `:`-prefixed name present and touched/dirty in the repo working tree (e.g., committed in a malicious PR, or created by an earlier step of an agent session) — no elevated privilege, no key leakage, no social engineering beyond ordinary repo content, consistent with the unprivileged attacker model. Because `:` is a valid character in POSIX filenames and git filenames generally, and because the plugin already goes out of its way to handle unicode/space-containing filenames (`core.quotePath=false`) but not colon-prefixed magic pathspecs, this is a realistic and repeatable gap rather than a theoretical one.

### Recommendation
Disable git pathspec magic globally for all invocations that treat file paths as literal filenames: add `-c core.literalPathspecs=true` to `GIT_CMD` in `plugins/security-guidance/hooks/gitutil.py`, or explicitly prefix each entry appended in `_diff_pathspec` with `:(literal)` before returning it. Add a regression test asserting that a touched file named `:(exclude)x.py` (or similar colon-prefixed name) still appears, and only that file appears, in the diff produced by `get_git_diff`.

### Proof of Concept
Unit test plan for `plugins/security-guidance/hooks/gitutil.py`:
1. In a temp git repo with an initial commit, create a top-level tracked file literally named `:(exclude)pwn.py` containing a deliberately "vulnerable-looking" line, commit it as the baseline.
2. Modify `:(exclude)pwn.py` (append a new vulnerable line) and call `get_git_diff(cwd, baseline_sha, paths=[os.path.join(cwd, ":(exclude)pwn.py")])`.
3. Assert (currently failing) that the returned diff is not `None` and contains the new line for `:(exclude)pwn.py` — i.e., the pathspec is treated as a literal filename, not as git pathspec magic.
4. Additionally assert `result.returncode == 0` isn't masking a mismatch: run the equivalent raw `git diff -- ':(exclude)pwn.py'` command directly and show it errors/misbehaves without `core.literalPathspecs=true`, then show it succeeds once that config is added, confirming the fix.