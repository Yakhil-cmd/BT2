### Title
Substring-only classification of "duplicate detection" comments allows unrelated Bot comments to trigger auto-close - ([File: scripts/auto-close-duplicates.ts])

### Summary
The `dupeComments` filter in `autoCloseDuplicates` classifies a comment as a "duplicate-detection" trigger purely by checking `comment.user.type === "Bot"` plus two free-text substrings (`"Found"` and `"possible duplicate"`), with no unique/unforgeable marker tying the comment to the actual duplicate-detection bot flow. Any GitHub Bot-authored comment on the repo that happens to contain both substrings (e.g., quoting issue text, logs, or another automation's output) will be misclassified as a genuine duplicate-detection comment and fed into `extractDuplicateIssueNumber`, which itself naively grabs the first `#\d+` pattern in the body.

### Finding Description
The classification logic is: [1](#0-0) 
This performs no structural validation — no hidden marker, no comment-author allowlist beyond the generic GitHub `type: "Bot"` field, and no correlation to the specific workflow that is supposed to produce these comments. Any bot account on the repository (CI bots, other automation, dependency bots, etc.) whose comment body incidentally contains the two literal substrings satisfies the filter.

Once selected as `lastDupeComment`, its body is passed directly into `extractDuplicateIssueNumber`, which just regex-matches the first `#(\d+)` or issue URL anywhere in the free text: [2](#0-1) 
There is no check that this number corresponds to an actual detected duplicate issue — it is whichever issue reference happens to appear first in the (unrelated) bot comment. If the remaining conditions hold (comment older than 3 days, no subsequent activity, no thumbs-down from the issue author) the script proceeds to call `closeIssueAsDuplicate` with that arbitrary extracted number: [3](#0-2) 

The invariant violated is that automation trigger classification should use an unforgeable, unambiguous marker (e.g., a hidden HTML comment/sentinel embedded only by the specific duplicate-detection workflow), not incidental substring matches on arbitrary bot text.

### Impact Explanation
If satisfied, an unrelated legitimate Bot comment causes a real, unintended issue to be closed with `state_reason: 'duplicate'` and labeled `duplicate`, plus a public bot comment referencing an arbitrary/incorrect issue number as the "duplicate of" target. This is an unauthorized automated state mutation (incorrect issue closure) driven by a classification flaw rather than the intended detection logic — a legitimate automation-integrity bug, though its blast radius is limited to issue triage state (labels/closed state/comments) in this repository, not code execution, secrets, or workspace compromise.

### Likelihood Explanation
Exploitability depends on a bot in the repository's automation ecosystem posting a comment that (a) is authored by a `type: "Bot"` account, (b) coincidentally or reflectively contains both `"Found"` and `"possible duplicate"`, (c) contains a `#number` or issue-URL reference, and (d) is followed by 3+ days of no further activity and no thumbs-down from the issue author. No concrete second bot flow producing such text was found in this repository during review, so exploitability in practice depends on the presence of other bot integrations (CI logs, dependency bots, third-party apps) whose free-form text could coincidentally match — this makes the scenario plausible but not confirmed as currently reachable in this codebase. The underlying classification defect itself, however, is real and demonstrable independent of a specific bot source.

### Recommendation
Replace substring matching with an unforgeable structural marker: embed a unique hidden identifier (e.g., an HTML comment token like `<!-- claude-code:duplicate-detection:v1 -->`) that only the actual duplicate-detection workflow writes, and require an exact match on that token (and ideally the specific bot login/ID that owns the workflow) instead of matching on `"Found"`/`"possible duplicate"` and generic `user.type === "Bot"`.

### Proof of Concept
Unit test `dupeComments` filter logic in isolation:
1. Construct a corpus of legitimate, non-duplicate-detection Bot comments (e.g., `"Found 3 possible duplicate keys in config.json during lint scan. See #42."`, or a CI log reflecting `"possible duplicate symbol ... Found in build output, ref #17"`), each with `user.type === "Bot"`.
2. Run these through the same filter predicate used in `scripts/auto-close-duplicates.ts` lines 164-169.
3. Assert that the filter returns `true` for these unrelated comments (false positive), and that `extractDuplicateIssueNumber` on lines 49-63 returns a non-null, arbitrary issue number extracted from unrelated text.
4. Expected assertion: false-positive rate > 0, proving the substring-match invariant is unsound and that `closeIssueAsDuplicate` could be invoked with an unrelated `duplicateOfNumber`.

### Citations

**File:** scripts/auto-close-duplicates.ts (L49-63)
```typescript
function extractDuplicateIssueNumber(commentBody: string): number | null {
  // Try to match #123 format first
  let match = commentBody.match(/#(\d+)/);
  if (match) {
    return parseInt(match[1], 10);
  }
  
  // Try to match GitHub issue URL format: https://github.com/owner/repo/issues/123
  match = commentBody.match(/github\.com\/[^\/]+\/[^\/]+\/issues\/(\d+)/);
  if (match) {
    return parseInt(match[1], 10);
  }
  
  return null;
}
```

**File:** scripts/auto-close-duplicates.ts (L164-169)
```typescript
    const dupeComments = comments.filter(
      (comment) =>
        comment.body.includes("Found") &&
        comment.body.includes("possible duplicate") &&
        comment.user.type === "Bot"
    );
```

**File:** scripts/auto-close-duplicates.ts (L243-258)
```typescript
    const duplicateIssueNumber = extractDuplicateIssueNumber(lastDupeComment.body);
    if (!duplicateIssueNumber) {
      console.log(
        `[DEBUG] Issue #${issue.number} - could not extract duplicate issue number from comment, skipping`
      );
      continue;
    }

    candidateCount++;
    const issueUrl = `https://github.com/${owner}/${repo}/issues/${issue.number}`;
    
    try {
      console.log(
        `[INFO] Auto-closing issue #${issue.number} as duplicate of #${duplicateIssueNumber}: ${issueUrl}`
      );
      await closeIssueAsDuplicate(owner, repo, issue.number, duplicateIssueNumber, token);
```
