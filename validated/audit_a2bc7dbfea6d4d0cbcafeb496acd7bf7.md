### Title
THROWAWAY-CODE refute exemption matches directory-name path prefixes without verifying import/reachability from production code, allowing production-reachable vulnerabilities to be reflexively refuted - ([File: plugins/security-guidance/hooks/review_api.py])

### Summary
The `build_refute_prompt` function's THROWAWAY-CODE clause instructs the adjudicating LLM to REFUTE a finding when "all touched files live under scripts/, dev/, tools/, examples/, testdata/, fixtures/, or behind a `__main__` dev guard." This exemption is keyed purely on path-string/directory-name matching and contains no instruction to trace whether the flagged file is actually imported/required by shipped, trusted-entrypoint code, unlike the adjacent DIFF-ANCHOR block which explicitly demands cited enabling-line evidence for off-diff candidates.

### Finding Description
`build_refute_prompt` in `plugins/security-guidance/hooks/review_api.py` (lines 268-270) contains:

```
"- THROWAWAY-CODE: all touched files live under scripts/, "
"dev/, tools/, examples/, testdata/, fixtures/, or behind "
"a __main__ dev guard.\n"
```

This is the sole condition for the exemption — it is a naming-convention/path-prefix test, not a reachability/trust test. Nothing in `AGENTIC_REFUTE_SYSTEM` or the rest of `build_refute_prompt` ( [1](#0-0) ) requires the model to Grep/trace whether a file under one of these directories is actually `import`ed by production code (e.g., `app/main.py`) before applying the exemption. This is in contrast to the DIFF-ANCHOR rules a few lines above, which explicitly require the model to "name that enabling diff line" or REFUTE ( [2](#0-1) ) — showing the prompt author is capable of writing reachability-aware refute conditions, but did not do so for THROWAWAY-CODE.

Practically: if an attacker's diff only touches `scripts/helper.py` (no other files in the same diff), the "all touched files" condition is trivially satisfied and the THROWAWAY-CODE exemption applies mechanically by path string, even if `scripts/helper.py` is already `import`ed by a trusted entrypoint elsewhere in the (unmodified) codebase. The refute-stage model has Read/Grep tools available (`AGENTIC_REFUTE_SYSTEM`, line 183-187) and *could* discover the import, but the prompt gives it no instruction or requirement to do so for this specific exemption — it only needs to observe the directory-name pattern to justify a REFUTE. This is a classifier/parser differential: the exemption's stated intent ("throwaway"/non-shipped code) does not match its actual test (path prefix), so a semantically production-reachable file can be laundered through a directory name that superficially matches the allowlist.

Note: the literal PoC scenario in the question (both `scripts/helper.py` and `app/main.py` touched in the *same* diff) would actually fail the "all touched files" condition, since `app/main.py` is not under an exempted directory — so that exact framing does not trigger the bug. The real exploitable variant requires the importing file (`app/main.py`) to be *unmodified* in the diff, with only the exempted-path file touched.

### Impact Explanation
This is a false-negative in the plugin's own review/export logic (the two-stage agentic security reviewer), one of the explicitly in-scope categories ("review/export logic"). A genuinely dangerous, always-imported helper placed under `scripts/`, `tools/`, `dev/`, etc. can have a real vulnerability (e.g., command injection, path traversal) suppressed by the automated reviewer solely because of its directory location, even though it is reachable from a trusted, shipped entrypoint. This undermines the core security guarantee of the plugin — that flagged findings in effectively-production code will survive adjudication — and can let real vulnerabilities merge undetected.

### Likelihood Explanation
The precondition is narrow but realistic: a contributor (or attacker with normal PR/commit access) adds or edits a helper file under one of the six exempted directory names while that file is (or becomes) reachable via import from already-shipped code, without touching the importing file in the same diff. This is a plausible and even common real-world pattern (utility scripts get promoted into being imported by application code without moving directories). Because the exemption is entirely prompt-text without a hard-coded reachability check or requirement that the LLM verify it, the refute stage may apply it purely via pattern matching, especially under the tool-call budget pressure noted elsewhere in the file (`AGENTIC_INVESTIGATE_SYSTEM` explicitly caps tool calls at "~15", line 119, encouraging shortcuts).

### Recommendation
Tighten the THROWAWAY-CODE clause in `build_refute_prompt` to require the same evidentiary bar as DIFF-ANCHOR: instruct the model to Grep the repository for `import`/`require`/`include` references to the touched file's module/symbol before applying the exemption, and REFUTE-via-THROWAWAY-CODE only if no reachable import from non-exempted code is found. Alternatively/additionally, perform a deterministic pre-check in code (outside the LLM prompt) that greps the full repo for references to the touched file's path/module name from files outside the exempted directories, and if found, strip the THROWAWAY-CODE option from the prompt for that candidate or flag it as `in_diff`-strength regardless of path.

### Proof of Concept
Integration test plan for `plugins/security-guidance/hooks/review_api.py`:
1. Construct a repo fixture where `app/main.py` (untouched in the diff, but present in the repo tree) contains `from scripts.helper import run_cmd`, and `scripts/helper.py` contains a command-injection sink introduced by the diff.
2. Build a diff that touches only `scripts/helper.py`.
3. Call `build_refute_prompt(candidates=[{filePath: "scripts/helper.py", vulnerableCode: "...", ...}], diff_text=diff)` and inspect the returned prompt string.
4. Assert that the prompt does NOT permit refuting the candidate via the THROWAWAY-CODE clause without also requiring cross-file import-reachability evidence — i.e., assert the rendered prompt contains an instruction to check whether the file is imported by non-exempted code before applying THROWAWAY-CODE (currently it does not; test should fail against current code and pass after the fix).
5. As a stronger regression test, simulate the refute-stage LLM call with a stubbed adjudicator that mechanically applies path-prefix matching, and assert the candidate is incorrectly placed in `refuted` under current prompt wording — demonstrating the current instruction set enables blind path-based refutation with no code-level barrier preventing it.

### Citations

**File:** plugins/security-guidance/hooks/review_api.py (L183-187)
```python
AGENTIC_REFUTE_SYSTEM = (
    "You adversarially verify security findings. You have "
    "Read/Grep over the repo. Default = SURVIVES unless you "
    "find concrete refuting evidence."
)
```

**File:** plugins/security-guidance/hooks/review_api.py (L222-231)
```python
        "DIFF-ANCHOR: candidates are sorted `in_diff` first, then "
        "`off_diff`. Process them in order. `in_diff` candidates "
        "use the standard KEEP/REFUTE bar above. `off_diff` "
        "candidates require STRICTER evidence: you must identify "
        "the specific +/- line in the diff that ENABLES the "
        "off-diff sink (a removed guard, a new caller, a changed "
        "argument feeding it). If you cannot name that enabling "
        "diff line, REFUTE the off_diff candidate. Additionally, "
        "REFUTE any off_diff candidate whose sink is already "
        "covered by a surviving in_diff candidate.\n\n"
```
