### Title
Naive `grep '\[gone\]'` line-match causes non-gone branches to be force-deleted with worktree removal - ([File: plugins/commit-commands/commands/clean_gone.md])

### Summary
The `clean_gone` command determines "stale/gone" branches by grepping the full text of `git branch -v` output for the literal substring `[gone]`, rather than parsing git's actual upstream-tracking status. Any local branch whose name or latest commit subject line contains that literal substring will be misclassified as gone and passed into a destructive pipeline that force-removes its worktree and force-deletes the branch with `git branch -D`.

### Finding Description
The deletion pipeline is:
```bash
git branch -v | grep '\[gone\]' | sed 's/^[+* ]//' | awk '{print $1}' | while read branch; do
  ...
  git worktree remove --force "$worktree"
  ...
  git branch -D "$branch"
done
``` [1](#0-0) 

`git branch -v` output lines are `<flag><branchname> <hash> <commit-subject>`. The command never inspects git's real upstream tracking status (which would require `git branch -vv` and a check for the exact `: gone]` marker within the tracking-ref brackets), it just greps the entire text line for the substring `[gone]`. Consequently:

1. If an attacker creates a local branch literally named e.g. `feature[gone]x`, the line `  feature[gone]x 1234567 some commit` matches the grep, `awk '{print $1}'` extracts `feature[gone]x` as `$branch`, and the script proceeds to force-remove any associated worktree and run `git branch -D feature[gone]x` — deleting a branch that was never pruned/gone.
2. Similarly, if the *commit subject* of an otherwise normal, actively-tracked branch contains the literal text `[gone]` (e.g., a commit message like `"fix: handle upstream [gone] state"`), the same line-level match occurs, and that unrelated branch gets force-deleted along with its worktree.

Since the tool being used is `git branch -D` (force delete, no merge-check) and `git worktree remove --force`, any uncommitted work in the worktree or unmerged commits on the branch are destroyed without confirmation. There is no allowlist, approval prompt, or secondary validation of tracking status before deletion — the command file simply instructs the agent to run this shell pipeline verbatim.

### Impact Explanation
This is an unintended destructive action: legitimate branches and their worktrees (potentially containing uncommitted or unmerged work) can be force-deleted based purely on a lexical coincidence in the branch name or commit message, not the actual git tracking state. This matches "unauthorized/unintended destructive file or git action" impact — data loss of branches/worktrees via a git automation flow triggered by ordinary repository content.

### Likelihood Explanation
Exploitability only requires the unprivileged attacker (or an ordinary contributor who happens to write `[gone]` in a branch name or commit message, or a collaborator pushing such a branch that gets checked out locally) to have such a branch present on the victim's machine when the `clean_gone` command is invoked. No special git server access or tracking-branch manipulation is needed — the substring can appear anywhere in the branch name or first line of the commit message reachable via ordinary repo content. This is fully repeatable and deterministic.

### Recommendation
Replace the substring grep with a parse against `git branch -vv` and only match when the upstream tracking annotation exactly contains `: gone]` (e.g. using a targeted regex like `grep -E '\[[^]]*: gone\]'` anchored to the tracking-ref bracket, or better, use `git for-each-ref --format='%(refname:short) %(upstream:track)' refs/heads` and filter on `[gone]` appearing specifically in the `%(upstream:track)` field). Never derive deletion candidates from a raw grep over commit subject text or branch names.

### Proof of Concept
Unit/integration test plan:
1. In a temp git repo, create branch `feature[gone]x` from `main`, with a normal upstream (or no upstream) — i.e., NOT actually gone.
2. Add a worktree for a second unrelated actively-tracked branch, and give its latest commit the message `"chore: handle [gone] state"`.
3. Run the current `clean_gone.md` pipeline verbatim.
4. Assert (fails today, should pass after fix): `feature[gone]x` still exists (`git rev-parse --verify feature[gone]x` succeeds) and the second branch's worktree still exists — i.e., the corrected implementation using real tracking-status parsing (`%(upstream:track)`) does not delete either, whereas the current grep-based script deletes both.

### Citations

**File:** plugins/commit-commands/commands/clean_gone.md (L28-40)
```markdown
   # Process all [gone] branches, removing '+' prefix if present
   git branch -v | grep '\[gone\]' | sed 's/^[+* ]//' | awk '{print $1}' | while read branch; do
     echo "Processing branch: $branch"
     # Find and remove worktree if it exists
     worktree=$(git worktree list | grep "\\[$branch\\]" | awk '{print $1}')
     if [ ! -z "$worktree" ] && [ "$worktree" != "$(git rev-parse --show-toplevel)" ]; then
       echo "  Removing worktree: $worktree"
       git worktree remove --force "$worktree"
     fi
     # Delete the branch
     echo "  Deleting branch: $branch"
     git branch -D "$branch"
   done
```
