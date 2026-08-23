Important: pr checkout already has explicit protection — `checkoutRun` in `pkg/cmd/pr/checkout/checkout.go` rejects branch names beginning with `-` before building any command queue: [1](#0-0) . That check covers `pr.HeadRefName`, and it runs before `cmdsForExistingRemote`/`cmdsForMissingRemote` build the `[]string{"checkout", localBranch}` args, so the `git/client.go` `CheckoutBranch`/`CheckoutNewBranch` equivalents used in that flow are not reachable with a leading-`-` branch name from PR checkout.

For `gh issue develop`, the `checkoutBranch` helper does call `gc.CheckoutBranch` and `gc.CheckoutNewBranch` with `checkoutBranch` (the linked-branch name) with **no leading-hyphen check** anywhere in `develop.go`: [2](#0-1) . However, tracing the actual git-argument construction in `git/client.go`:

- `CheckoutNewBranch` places `branch` as the required argument to `-b` and `track` as the required argument to `--track`: [3](#0-2) . Because `-b`/`--track` are options that mandatorily consume the next token as their value, git's option parser treats a `-`-prefixed value here as a literal value, not as a re-parsed flag — this is not exploitable as an option-injection.
- `DeleteLocalBranch` places `branch` as the required argument to `-D`, which is the same safe pattern: [4](#0-3) .
- `CheckoutBranch`, however, passes `branch` as a bare positional argument with no `--` separator: `args := []string{"checkout", branch}` [5](#0-4) . This is the one function in this group that lacks the defensive `--` separator that other functions in the same file use, e.g. `ShowRefs` (`"show-ref", "--verify", "--"`), `WorktreeRemove`, `IsIgnored`, `RemoteURL` all insert `"--"` before the positional path/ref argument.

So the theoretically weak point is `CheckoutBranch`, but I could not find any reachable attacker-controlled call site that supplies a `-`-prefixed branch name to it without an upstream guard:
- The `pr checkout` path explicitly rejects leading `-` in `pr.HeadRefName` before it's ever used to build `{"checkout", localBranch}` args.
- The `issue develop` path (`checkoutBranch` in `develop.go`) does call `gc.CheckoutBranch(ctx.Background(), checkoutBranch)` unguarded, and `checkoutBranch` originates from `api.CreateLinkedBranch`'s response [6](#0-5) . This is a real gap: there is no leading-`-` check on `branchName` in the `develop` command, unlike `pr checkout`.

Whether this is exploitable depends on whether GitHub's GraphQL `createLinkedBranch` mutation (or GitHub's ref-name validation) can ever actually produce/store a ref name beginning with `-`. I do not have visibility into GitHub's server-side ref-name validation from this codebase, and the client code itself performs no validation on the returned `branchName` before passing it to `gc.HasLocalBranch`, `gc.CheckoutBranch`, or `gc.CheckoutNewBranch`. Given git's own `check-ref-format` rules (used both by the git CLI and, presumably, by GitHub's backend when creating refs) do not explicitly forbid a leading hyphen in a ref component, it is plausible but unconfirmed that GitHub could allow it — I cannot verify GitHub's server-side behavior from the client repo alone.

### Title
Missing leading-hyphen guard on linked-branch name before `git.Client.CheckoutBranch` in `gh issue develop` - (File: pkg/cmd/issue/develop/develop.go)

### Summary
`pkg/cmd/issue/develop/develop.go`'s `checkoutBranch` passes the linked-branch name returned by `api.CreateLinkedBranch` (or an existing linked branch's name) directly into `git.Client.CheckoutBranch`, which builds `{"checkout", branch}` with no `--` separator, unlike the equivalent `pr checkout` code path which explicitly rejects branch names beginning with `-`.

### Finding Description
`developRunCreate` obtains `branchName` from `api.CreateLinkedBranch(...)` (a GraphQL mutation) and passes it unchecked to `checkoutBranch(opts, branchRepo, branchName, worktreeTarget)` [6](#0-5) . In `checkoutBranch`, if the branch already exists locally, `gc.CheckoutBranch(ctx.Background(), checkoutBranch)` is invoked [7](#0-6) . `git.Client.CheckoutBranch` builds `args := []string{"checkout", branch}` with no `--` separator before the positional branch argument [5](#0-4) . By contrast, `pr checkout` explicitly guards against this exact case (`strings.HasPrefix(pr.HeadRefName, "-")`) before any command construction [1](#0-0) , showing the maintainers are aware of this class of issue but the guard was not applied to the `issue develop` code path.

### Impact Explanation
If a branch name beginning with `-` could reach `git checkout -somebranch`, git would interpret it as an unrecognized/valid option rather than a branch name (e.g., `--orphan`, `--detach`, or other flags), potentially causing unexpected checkout behavior. This falls into GitHub's "command injection via crafted input" bounty class at low/moderate severity, since the practical outcome is limited to git-option confusion (most `checkout` single-dash/double-dash options don't yield arbitrary code execution) rather than direct RCE.

### Likelihood Explanation
Exploitability hinges entirely on whether GitHub's backend (`createLinkedBranch` GraphQL mutation) will ever create/return a ref name beginning with `-`. I could not verify this constraint from the client codebase; if GitHub's server-side validation already rejects such names (likely, since git's `check-ref-format` and GitHub's own branch-name UI validation are typically strict), this path is not exploitable in practice. Without confirming the server-side behavior, likelihood is uncertain/low.

### Recommendation
Add the same leading-hyphen validation used in `pr checkout` (`pkg/cmd/pr/checkout/checkout.go:150-152`) to `checkoutBranch` in `pkg/cmd/issue/develop/develop.go` before using `checkoutBranch` name in any git command, and/or fix `git.Client.CheckoutBranch` in `git/client.go` to insert a `"--"` separator (`args := []string{"checkout", "--", branch}` is not valid for switching branches via `checkout <branch>` semantics since `--` after checkout changes meaning for paths, so the correct fix is `args := []string{"checkout", branch, "--"}` is also wrong; the idiomatic git-safe fix is to reject/validate branch names starting with `-` at the call site, matching the `pr checkout` pattern).

### Proof of Concept
Add a unit test to `pkg/cmd/issue/develop/develop_test.go` (or a git-stub test) that:
1. Mocks `api.CreateLinkedBranch` to return `branchName = "-b"` (or `--upload-pack=...` style malicious value).
2. Runs `developRunCreate` with `opts.Checkout = true` and asserts on the constructed git command-line arguments (via a `GitClient` command-recording stub) that `checkout` is invoked with a bare `-b`-prefixed token as the second positional argument.
3. Compare against `pkg/cmd/pr/checkout/checkout_test.go`, which should already contain (or should add) a test asserting `strings.HasPrefix(pr.HeadRefName, "-")` returns an error — confirming the `develop.go` path lacks the equivalent assertion.

### Citations

**File:** pkg/cmd/pr/checkout/checkout.go (L150-152)
```go
	if strings.HasPrefix(pr.HeadRefName, "-") {
		return fmt.Errorf("invalid branch name: %q", pr.HeadRefName)
	}
```

**File:** pkg/cmd/issue/develop/develop.go (L260-266)
```go
		opts.IO.StartProgressIndicatorWithLabel("Creating linked branch")
		createdBranchName, err := api.CreateLinkedBranch(apiClient, branchRepo.RepoHost(), repoID, issue.ID, branchID, opts.Name)
		if err != nil {
			return err
		}
		branchName = createdBranchName
	}
```

**File:** pkg/cmd/issue/develop/develop.go (L405-417)
```go
	if gc.HasLocalBranch(ctx.Background(), checkoutBranch) {
		if err := gc.CheckoutBranch(ctx.Background(), checkoutBranch); err != nil {
			return err
		}

		if err := gc.Pull(ctx.Background(), baseRemote.Name, checkoutBranch); err != nil {
			_, _ = fmt.Fprintf(opts.IO.ErrOut, "%s warning: not possible to fast-forward to: %q\n", opts.IO.ColorScheme().WarningIcon(), checkoutBranch)
		}
	} else {
		if err := gc.CheckoutNewBranch(ctx.Background(), baseRemote.Name, checkoutBranch); err != nil {
			return err
		}
	}
```

**File:** git/client.go (L653-664)
```go
func (c *Client) DeleteLocalBranch(ctx context.Context, branch string) error {
	args := []string{"branch", "-D", branch}
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
