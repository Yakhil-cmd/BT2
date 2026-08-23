### Title
Argument injection via attacker-controlled `LinkedBranch.BranchName` in `git.Client.CheckoutBranch` - ([File: pkg/cmd/issue/develop/develop.go])

### Summary
`checkoutBranch` in `pkg/cmd/issue/develop/develop.go` passes the API-derived `checkoutBranch` (sourced from `LinkedBranch.BranchName`) directly as a positional argument to `git checkout <branch>` with no `--` separator, and `git.Client.CheckoutBranch` in `git/client.go` builds `args := []string{"checkout", branch}` without any leading-dash protection.

### Finding Description
`developRunCreate` obtains `branchName` from `api.CreateLinkedBranch`/`api.ListLinkedBranches` (attacker-influenced, since the attacker controls the repo the mutation targets) and passes it unchanged into `checkoutBranch(opts, branchRepo, branchName, worktreeTarget)` [1](#0-0) . Inside `checkoutBranch`, if `gc.HasLocalBranch(...)` is true, `gc.CheckoutBranch(ctx.Background(), checkoutBranch)` is invoked [2](#0-1) , whose implementation is `args := []string{"checkout", branch}` with no `--` guard before the branch name [3](#0-2) .

However, two mitigating conditions apply that prevent this from being a straightforwardly exploitable finding in this code path:
1. `CheckoutBranch` (positional, unguarded) is only reached when `gc.HasLocalBranch` already reports a *local* ref `refs/heads/<name>` exists — meaning a branch by that exact literal name must already exist on the victim's machine before this call. The initial `Fetch` call only creates `refs/remotes/<remote>/<name>`, not `refs/heads/<name>` [4](#0-3) , so on first run the `else` branch is taken instead, calling `gc.CheckoutNewBranch` with `args := []string{"checkout", "-b", branch, "--track", track}` [5](#0-4) . Because `branch` here is consumed as the mandatory value of the `-b` flag (git's option parser treats the token immediately following a flag requiring a value as that value regardless of a leading dash), this call is not exploitable as flag injection.
2. Git itself refuses to create or resolve refs whose name (or any slash-separated component) begins with a dash (`check_refname_format` rejects such refnames as part of Git's own ref-name validation, a fix specifically intended to close this class of `git checkout <ref>`-style argument-injection bug). This means `git checkout -b '--upload-pack=...' --track origin/--upload-pack=...` would itself fail with an invalid-refname error from git before any flag confusion could occur, and consequently no local branch named `--upload-pack=...` could ever come to exist to satisfy `HasLocalBranch` and reach the vulnerable unguarded `CheckoutBranch` call.

I was not able to fully verify Git's exact behavior/version-dependence for ref names starting with `-` from within this repository's indexed contents (this is enforced by the external `git` binary, not by this Go codebase), so there is residual uncertainty about whether some malformed-but-git-accepted string (e.g. containing a leading `-` only after a `/`, or some other confusing character combination) could still slip through `check_refname_format` while also being parsed as a flag by `git checkout`. That would require testing against a real `git` binary, which is outside the scope of static code review here.

### Impact Explanation
If Git's own ref-name validation did not reject leading-dash branch names, this would allow local flag injection into `git checkout` (e.g., `--orphan=<value>` or similar), yielding local repository state corruption. However, given git's built-in refname validation rejecting refs beginning with `-`, and given `CheckoutNewBranch`'s safe placement of `branch` as the value of the `-b` flag, no concrete `NO_INJECTED_EXECUTION` violation is demonstrated within `checkoutBranch`/`CheckoutBranch`/`CheckoutNewBranch`/`Fetch`/`Pull` as currently reachable from `gh issue develop`.

### Likelihood Explanation
Low/unconfirmed: the unguarded `CheckoutBranch` call is only reachable if a local branch with the exact malicious literal name already exists, which itself requires successfully running `git checkout -b <malicious-name>` earlier — a step that git's refname validation is expected to block for names beginning with `-`.

### Recommendation
Even though Git's own validation likely blocks this today, defense-in-depth is warranted: (1) add an explicit `--` separator before the branch name in `CheckoutBranch`'s `args := []string{"checkout", "--", branch}`; (2) reject/quote `LinkedBranch.BranchName` values beginning with `-` before use in `checkoutBranch`, `Fetch`'s refspec, and worktree commands; (3) add a regression test asserting `git.Client.CheckoutBranch` always emits `checkout -- <name>` so a future refactor or Git behavior change cannot reopen this class of bug.

### Proof of Concept
Not conclusively reproducible from indexed code alone — would require an integration test with the real `git` binary attempting `git branch --edit-description`/`git check-ref-format --branch -- '--upload-pack=x'` to confirm rejection, plus a `run.Stub`-based unit test on `git.Client.CheckoutBranch`/`CheckoutNewBranch` asserting exact argv ordering (`checkout`, `-b`, name, `--track`, target vs. `checkout`, name) to document the current (safe, due to external git validation) behavior and catch regressions if the `--` separator is ever removed from `CheckoutNewBranch` or if `CheckoutBranch`'s unguarded positional argument is exercised on Git versions/configurations that don't enforce the leading-dash refname restriction.

### Citations

**File:** pkg/cmd/issue/develop/develop.go (L260-287)
```go
		opts.IO.StartProgressIndicatorWithLabel("Creating linked branch")
		createdBranchName, err := api.CreateLinkedBranch(apiClient, branchRepo.RepoHost(), repoID, issue.ID, branchID, opts.Name)
		if err != nil {
			return err
		}
		branchName = createdBranchName
	}

	if branchName == "" {
		return fmt.Errorf("failed to create linked branch: API returned empty branch name")
	}

	opts.IO.StopProgressIndicator()

	if reusedExisting && opts.IO.IsStdoutTTY() {
		fmt.Fprintf(opts.IO.ErrOut, "Using existing linked branch %q\n", branchName)
	}

	// Remember which branch to target when creating a PR.
	if opts.BaseBranch != "" {
		if err := opts.GitClient.SetBranchConfig(ctx.Background(), branchName, git.MergeBaseConfig, opts.BaseBranch); err != nil {
			return err
		}
	}

	fmt.Fprintf(opts.IO.Out, "%s/%s/tree/%s\n", branchRepo.RepoHost(), ghrepo.FullName(branchRepo), branchName)

	return checkoutBranch(opts, branchRepo, branchName, worktreeTarget)
```

**File:** pkg/cmd/issue/develop/develop.go (L377-381)
```go
	gc := opts.GitClient

	if err := gc.Fetch(ctx.Background(), baseRemote.Name, fmt.Sprintf("+refs/heads/%[1]s:refs/remotes/%[2]s/%[1]s", checkoutBranch, baseRemote.Name)); err != nil {
		return err
	}
```

**File:** pkg/cmd/issue/develop/develop.go (L405-408)
```go
	if gc.HasLocalBranch(ctx.Background(), checkoutBranch) {
		if err := gc.CheckoutBranch(ctx.Background(), checkoutBranch); err != nil {
			return err
		}
```

**File:** git/client.go (L666-677)
```go
func (c *Client) CheckoutBranch(ctx context.Context, branch string) error {
	args := []string{"checkout", branch}
	cmd, err := c.Command(ctx, args...)
	if err != nil {
		return err
	}
	_, err = cmd.Output()
	if err != nil {
		return err
	}
	return nil
}
```

**File:** git/client.go (L679-691)
```go
func (c *Client) CheckoutNewBranch(ctx context.Context, remoteName, branch string) error {
	track := fmt.Sprintf("%s/%s", remoteName, branch)
	args := []string{"checkout", "-b", branch, "--track", track}
	cmd, err := c.Command(ctx, args...)
	if err != nil {
		return err
	}
	_, err = cmd.Output()
	if err != nil {
		return err
	}
	return nil
}
```
