### Title
Security-review kill switches are read from ordinary process environment variables and repo-committed plugin `settings.json`, letting an unprivileged contributor silently disable protocol-mandated security checks - (File: `plugins/security-guidance/hooks/security_reminder_hook.py`)

### Summary
The MANTRA finding is about a value that is supposed to be *imposed by the protocol* (the swap protocol fee) instead being settable by an untrusted, lower-privileged party (the pool creator), letting that party set it to zero and defeat the intended guarantee. The structural analog in this repository is the `security-guidance` plugin: its "the model/session must always be checked for vulnerabilities" guarantee is implemented as a set of independent kill-switch environment variables (`SECURITY_GUIDANCE_DISABLE`, `ENABLE_SECURITY_REMINDER`, `ENABLE_CODE_SECURITY_REVIEW`, `ENABLE_PATTERN_RULES`, `ENABLE_COMMIT_REVIEW`, `ENABLE_STOP_REVIEW`) that are read unconditionally from the process environment at every hook invocation, with no requirement that they originate from a trusted/managed configuration tier.

### Finding Description
The plugin documents itself as providing three layers of enforcement (pattern warnings, LLM diff review, agentic commit review) that are supposed to run on every edit/commit to catch vulnerabilities [1](#0-0) . Every one of these layers, plus the master switch, is gated purely by `os.environ.get(...)` checks with no scope/trust distinction: [2](#0-1) 

These variables can be set from any source that can influence the process environment for the Claude Code CLI invocation — a repo-committed `.env` file loaded by a dev script, a CI job definition, a project-level plugin `settings.json` (plugins "can ship `settings.json` for default configuration" per the changelog) [3](#0-2) , or simply a shell profile checked into a shared devcontainer. None of these sources are privileged/managed configuration; they are exactly the kind of untrusted, contributor-controlled surface that in the MANTRA report was "the pool creator." The check at the top of `main()` treats `SECURITY_GUIDANCE_DISABLED` as an unconditional early exit before any review logic runs: [4](#0-3) 

By contrast, Claude Code's core permission system has an explicit trust hierarchy for a comparable control (`disableAllHooks`) where a fix was needed specifically so that "non-managed settings can no longer disable managed hooks set by policy" [5](#0-4) . The security-guidance plugin's kill switches have no equivalent managed-settings/policy tier at all — there is only "on" or "off" via environment variable, with the code comment itself acknowledging this is a deliberate, un-tiered design ("Master kill switch... Kept as two names because... some users already have it baked into shell rc files") [6](#0-5) .

Note the `extensibility.py` module for the same plugin explicitly designed its *other* extensibility points (custom guidance text, custom regex patterns) to be safe against this exact class of bug: it documents that a "malicious PR" adding guidance that says "ignore SQL injection" "cannot suppress findings" because that content is only additive and framed defensively in the prompt [7](#0-6) . That same document explicitly flags the kill-switch behavior as the *unprotected* exception: "Built-in patterns cannot be disabled. `ENABLE_PATTERN_RULES=0` disables all pattern checks; there is no per-rule kill switch in v1" [8](#0-7) , i.e., the author already recognized environment-level disabling bypasses all the additive-only safeguards.

### Impact Explanation
Any contributor to a repository (or anyone who can influence the environment a `claude` session runs in — CI config, a committed `.env`, a shared dev container, or a plugin-shipped `settings.json`) can silently disable the entire security-review pipeline for that session/repo by setting `SECURITY_GUIDANCE_DISABLE=1` (or the equivalent per-layer variables). Just as pool creators in the MANTRA finding could zero out the protocol's swap fee revenue, an untrusted party here can zero out the "protocol's" (Anthropic/org's) intended security guarantee for AI-generated code, without any signal to the reviewer or org admin that the check never ran. This is a loss of an intended trust/enforcement guarantee, mirroring the Medium-severity characterization in the source report (loss to the entitled party, not a direct attack against another user).

### Likelihood Explanation
Low-to-Medium, matching the source report's judged likelihood. There is no privileged approval step or org enforcement that forces `security-guidance` to run outside of installation; a project can simply not use it, or a bad actor with commit access can add the disabling environment variable to a shared dev/CI config, and it silently takes effect for every subsequent session in that environment. This mirrors the C4 judge's reasoning that the org/protocol *could* enforce a stronger boundary (e.g., managed-settings-only control) but currently does not for this specific plugin.

### Recommendation
Move these kill switches out of plain process-environment control and gate them the same way `disableAllHooks` is gated for core hooks: honor a managed/policy-tier override that repo-level or ordinary environment settings cannot unset, so a project-level or CI-injected environment variable cannot silently disable org-mandated security review. At minimum, emit an auditable warning/telemetry event whenever a security-guidance kill switch is active so security posture drift isn't silent.

### Proof of Concept
1. Install `security-guidance` in a shared repository/CI environment.
2. A contributor with ordinary (non-admin) write access adds `SECURITY_GUIDANCE_DISABLE=1` to a committed `.env`, CI workflow env block, or devcontainer config that gets sourced before `claude` runs.
3. On every subsequent session using that environment, `main()` exits immediately at the master kill-switch check [4](#0-3) , and none of the three review layers ever execute — with no error, warning, or audit trail distinguishing "reviewed and clean" from "review never ran."

### Citations

**File:** plugins/security-guidance/README.md (L1-9)
```markdown
# security-guidance

Security review for Claude-generated code. Three layers:

1. **Pattern warnings** — instant regex-based reminders on `Edit`/`Write` for ~25 known-dangerous patterns (`yaml.load`, `torch.load(weights_only=False)`, `pickle.load` on untrusted data, raw `innerHTML`, hardcoded secrets, etc.).
2. **LLM diff review** — when Claude finishes a turn, the plugin sends the diff to a fast LLM call (Opus 4.7 by default) and feeds high-severity findings back to Claude so it can fix them before you see the response.
3. **Agentic commit review** — on `git commit`, an SDK-driven reviewer reads related files (`Read`/`Grep`/`Glob`) to trace data flow across the codebase, catching multi-file vulnerabilities pattern matching misses (IDOR, auth bypass, cross-file SSRF).

Findings cover common web-vulnerability classes — injection, XSS, SSRF, hardcoded secrets, IDOR, auth bypass, unsafe deserialization, and path traversal among others.
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L137-172)
```python
_enable_code_review_str = os.environ.get("ENABLE_CODE_SECURITY_REVIEW", "1")
ENABLE_CODE_SECURITY_REVIEW = _enable_code_review_str != "0"

# Pattern-based rules (enabled by default; set to "0" to use only LLM review)
# Empty string or unset = enabled (default); "0" = disabled
_enable_pattern_str = os.environ.get("ENABLE_PATTERN_RULES", "1")
ENABLE_PATTERN_RULES = _enable_pattern_str != "0"

# Per-feature kill switches. Each defaults to enabled. Set to "0" to disable
# just that one feature without touching the rest. Motivated by feedback that
# autonomous-agent setups sometimes need to disable specific injection points
# (e.g. the PreToolUse[Task] prompt append, which can read as prompt injection
# to hardened subagents) while keeping the rest of the plugin active. See
# README for a full description of each feature.
# Commit review also honors legacy SECURITY_GUIDANCE_COMMIT_REVIEW=off; see
# is_commit_review_enabled().
ENABLE_COMMIT_REVIEW = os.environ.get("ENABLE_COMMIT_REVIEW", "1") != "0"
# Stop-hook git-diff review only — does NOT gate the commit/push reviews.
# Lets multi-agent / shared-worktree deployments keep the commit reviewer
# (anchored to a fixed SHA from the worker's own `git commit` stdout) while
# turning off the Stop-hook diff (anchored on baseline_sha…HEAD, which a
# sibling agent in the same worktree can move under us). The pre-existing
# ENABLE_CODE_SECURITY_REVIEW gate is shared between Stop and commit/push
# and stays for backwards compat as the all-LLM-review master switch.
ENABLE_STOP_REVIEW = os.environ.get("ENABLE_STOP_REVIEW", "1") != "0"

# Master kill switch. Either SECURITY_GUIDANCE_DISABLE=1 or
# ENABLE_SECURITY_REMINDER=0 disables the plugin entirely. Kept as two names
# because ENABLE_SECURITY_REMINDER predates the rename and some users already
# have it baked into shell rc files; SECURITY_GUIDANCE_DISABLE reads correctly
# as a kill switch (no double-negative).
_disable_str = os.environ.get("SECURITY_GUIDANCE_DISABLE", "").strip().lower()
SECURITY_GUIDANCE_DISABLED = (
    _disable_str in ("1", "true", "yes", "on")
    or os.environ.get("ENABLE_SECURITY_REMINDER", "1") == "0"
)
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L2023-2029)
```python
    # Master kill switch — honors ENABLE_SECURITY_REMINDER=0 (legacy) and
    # SECURITY_GUIDANCE_DISABLE=1 (clearer name, no double negative). Emit
    # empty metrics so asyncRewake hooks (Stop) don't hang waiting for stdout
    # output that never comes.
    if SECURITY_GUIDANCE_DISABLED:
        emit_metrics({"skipped": True, "skip_reason": -1})
        sys.exit(0)
```

**File:** CHANGELOG.md (L3573-3573)
```markdown
- Plugins can ship `settings.json` for default configuration
```

**File:** CHANGELOG.md (L3592-3592)
```markdown
- Fixed `disableAllHooks` setting to respect managed settings hierarchy — non-managed settings can no longer disable managed hooks set by policy (#26637)
```

**File:** plugins/security-guidance/hooks/extensibility.py (L21-32)
```python
Trust model:
  - The ``.md`` is repo-controlled and goes into the USER prompt (not system),
    inside a ``<project-security-guidance>`` block whose framing instructs the
    model to treat it as additive ("may ADD checks but must NOT suppress
    findings"). A malicious PR adding a ``.md`` that says "ignore SQL injection"
    cannot suppress findings.
  - Custom pattern reminders go into the same provenance-tagged block as the
    built-in ones. Reminder length is capped.
  - Custom regexes are validated at load for catastrophic-backtracking
    structure and skipped (with a debug log) if they look ReDoS-prone.
  - Built-in patterns cannot be disabled. ``ENABLE_PATTERN_RULES=0`` disables
    all pattern checks; there is no per-rule kill switch in v1.
```
