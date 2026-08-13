### Title
Multi-line label string bypasses valid-label allowlist via `grep -F` newline-splitting - ([File: scripts/edit-issue-labels.sh])

### Finding Description
`edit-issue-labels.sh` is invoked by the `triage-issue` slash command with `allowed-tools: Bash(./scripts/edit-issue-labels.sh:*)`, and the labels it applies are chosen by an LLM analyzing untrusted issue body/comment text supplied by any unprivileged issue author [1](#0-0) [2](#0-1) . The script's only safety control preventing invented/arbitrary label names from being applied is:

```
VALID_LABELS=$(gh label list --limit 500 --json name --jq '.[].name')
for label in "${ADD_LABELS[@]}"; do
  if echo "$VALID_LABELS" | grep -qxF "$label"; then
    FILTERED_ADD+=("$label")
  fi
done
``` [3](#0-2) 

`grep -F` treats a PATTERN operand containing an embedded newline as multiple alternate literal patterns (one per line), each matched independently against the input with OR semantics. If `$label` is a multi-line string such as `"bug\nnot-a-real-label"`, `grep -qxF "$label"` succeeds because the first line (`bug`) exactly matches an existing valid label — even though the *entire* `$label` value is appended verbatim to `FILTERED_ADD` via `FILTERED_ADD+=("$label")` [4](#0-3) . That unsanitized multi-line string is then passed straight through as a single `--add-label` value to `gh issue edit` [5](#0-4) , defeating the intended "only labels that exist in the repo" guarantee that both the script comment and the `triage-issue.md` instructions ("You may ONLY use labels from this list. Never invent new labels.") rely on [2](#0-1) .

### Impact Explanation
This breaks the trust boundary the script is specifically designed to enforce: that an LLM-driven, untrusted-content-influenced automation can only ever apply pre-existing, maintainer-approved labels to an issue. An attacker who can influence the triage agent's tool call (via prompt injection embedded in an issue body/comment) can smuggle an arbitrary attacker-chosen string through the allowlist check and have it submitted to `gh issue edit --add-label`, resulting in unauthorized label creation/application on a GitHub issue in the `anthropics/claude-code` repo — an allowlist/validation bypass in an automated write-access workflow.

### Likelihood Explanation
Exploitation requires two things: (1) successfully prompt-injecting the triage LLM agent to emit a `--add-label` argument containing an embedded newline (feasible since Bash tool arguments can contain arbitrary bytes, e.g. `$'bug\nmalicious'`), and (2) the automation being triggered on attacker-created issues/comments, which happens automatically for every public issue. The bypass mechanism itself is deterministic and trivially reproducible in isolation without any GitHub interaction.

### Recommendation
Do not match unsanitized attacker-influenced strings with `grep -F` against a multi-line haystack of valid names. Reject any label argument containing embedded newlines/control characters before comparison, and validate equality per-element with an exact string comparison (e.g. iterate `VALID_LABELS` into an array and compare with `[[ "$valid" == "$label" ]]`) rather than piping through `grep`.

### Proof of Concept
```bash
#!/usr/bin/env bash
# Demonstrates the grep -F newline-splitting bypass in isolation.
VALID_LABELS=$'bug\nenhancement\nquestion'
label=$'bug\nnot-a-real-label'

if echo "$VALID_LABELS" | grep -qxF "$label"; then
  echo "BYPASS: '$label' treated as valid even though 'not-a-real-label' is not a real label"
  exit 0
else
  echo "no bypass"
  exit 1
fi
```
Expected assertion: the script prints `BYPASS: ...` and exits 0, proving that a label string containing an embedded newline whose first line matches an existing label is accepted by the allowlist check in full (unsanitized), which in `edit-issue-labels.sh` is subsequently forwarded verbatim to `gh issue edit --add-label`.

### Citations

**File:** .claude/commands/triage-issue.md (L1-8)
```markdown
---
allowed-tools: Bash(./scripts/gh.sh:*),Bash(./scripts/edit-issue-labels.sh:*)
description: Triage GitHub issues by analyzing and applying labels
---

You're an issue triage assistant. Analyze the issue and manage labels.

IMPORTANT: Don't post any comments or messages to the issue. Your only actions are adding or removing labels.
```

**File:** .claude/commands/triage-issue.md (L27-27)
```markdown
1. Run `./scripts/gh.sh label list` to fetch the available labels. You may ONLY use labels from this list. Never invent new labels.
```

**File:** scripts/edit-issue-labels.sh (L44-53)
```shellscript
# Fetch valid labels from the repo
VALID_LABELS=$(gh label list --limit 500 --json name --jq '.[].name')

# Filter to only labels that exist in the repo
FILTERED_ADD=()
for label in "${ADD_LABELS[@]}"; do
  if echo "$VALID_LABELS" | grep -qxF "$label"; then
    FILTERED_ADD+=("$label")
  fi
done
```

**File:** scripts/edit-issue-labels.sh (L67-77)
```shellscript
GH_ARGS=("issue" "edit" "$ISSUE")

for label in "${FILTERED_ADD[@]}"; do
  GH_ARGS+=("--add-label" "$label")
done

for label in "${FILTERED_REMOVE[@]}"; do
  GH_ARGS+=("--remove-label" "$label")
done

gh "${GH_ARGS[@]}"
```
