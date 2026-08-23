### Title
Missing leading-dash guard on attacker-controlled linked-branch names allows git argument injection in `gh issue develop --checkout` - ([File: pkg/cmd/issue/develop/develop.go])

### Summary
`checkoutBranch` in `pkg/cmd/issue/develop/develop.go` passes a branch name returned by `api.CreateLinkedBranch`/`api.ListLinkedBranches` directly to `gc.CheckoutBranch`/`gc.CheckoutNewBranch` without ever checking for a leading `-`, unlike `pkg/cmd/pr/checkout/checkout.go` which explicitly rejects `pr.HeadRefName` when it starts with `-` before it is ever placed into a git argv. This name is attacker-influenceable because `--name` supplied by the invoking user is echoed back by the mutation/query response and also flows through `findExistingLinkedBranchName`/`ListLinkedBranches`, both of which trust whatever `Ref.Name` the GraphQL response contains.

### Finding Description
- `developRunCreate` obtains `branchName` from `api.CreateLinkedBranch(...)` (`api/queries_branch_issue_reference.go:15-49`, returning `mutation.CreateLinkedBranch.LinkedBranch.Ref.Name`) or from `findExistingLinkedBranchName`, which reads `branch.BranchName` sourced from `api.ListLinkedBranches`'s `node.Ref.Name` [1](#0-0) . Neither function validates the ref name.
- `developRunCreate` then calls `checkoutBranch(opts, branchRepo, branchName, worktreeTarget)` [2](#0-1) .
- Inside `checkoutBranch`, the value is used unsanitized as a positional git argument: `gc.CheckoutBranch(ctx.Background(), checkoutBranch)` when a local branch with that name exists, or `gc.CheckoutNewBranch(ctx.Background(), baseRemote.Name, checkoutBranch)` otherwise [3](#0-2) . There is no `strings.HasPrefix(checkoutBranch, "-")` check anywhere in `develop.go`.
- By contrast, `pkg/cmd/pr/checkout/checkout.go` explicitly guards against this exact class of injection for `pr.HeadRefName` before building any command queue: `if strings.HasPrefix(pr.HeadRefName, "-") { return fmt.Errorf("invalid branch name: %q", pr.HeadRefName) }` [4](#0-3) , and that same file later constructs the equivalent bare `checkout <branch>` invocation, e.g. `cmds = append(cmds, []string{"checkout", localBranch})` [5](#0-4) , which is exactly the pattern `develop.go`'s `gc.CheckoutBranch` reduces to but without the corresponding guard.
- Because the branch name for a linked branch is a GitHub `Ref` name, GitHub's ref-name rules permit many characters but a name beginning with `-` is a syntactically valid git ref component; nothing in `CreateLinkedBranch`/`ListLinkedBranches` rejects it, and `checkoutBranch` never re-validates it before using it as a bare CLI token.

### Impact Explanation
If a linked branch name begins with `-` (e.g., `--orphan`, `--upload-pack=evil`, `--force`), and the victim runs `gh issue develop <n> --checkout` (or `--checkout --name <same-name>` to trigger reuse), the resulting `git checkout <name>` invocation may interpret the value as a flag instead of a branch reference, causing unexpected git behavior (e.g., silently creating an orphan branch, forcing a discard of local changes, or otherwise altering git's argument parsing) instead of the intended checkout. This matches GitHub's "unexpected local command execution / argument injection via untrusted input" bounty class — though the concrete blast radius is bounded to whatever git flags are reachable from `checkout`'s argument position (data/state corruption risk on the victim's working tree), it does not by itself yield arbitrary code execution.

### Likelihood Explanation
Exploitation requires that: (1) the issue and its linked branches are visible to and can be interacted with by the attacker (an issue linked-branch feature typically requires write/triage access to create via API, but any user able to view/list linked branches created by others, or a maintainer who accepts an externally-suggested branch name via `--name`, could trigger it), and (2) the victim runs `gh issue develop --checkout` against that issue. This is a narrower precondition than the PR-checkout case (which works against any public PR), which is presumably why `checkout.go` already carries the explicit guard while `develop.go` was missed.

### Recommendation
Add the same leading-dash validation used in `pkg/cmd/pr/checkout/checkout.go:150-152` to `pkg/cmd/issue/develop/develop.go`, rejecting any `branchName` returned by `api.CreateLinkedBranch`/`api.ListLinkedBranches` (and any name resolved via `findExistingLinkedBranchName`) that starts with `-`, before it reaches `checkoutBranch`'s `gc.Fetch`, `gc.CheckoutBranch`, or `gc.CheckoutNewBranch` calls.

### Proof of Concept
Add a table-driven case to `pkg/cmd/issue/develop/develop_test.go` mirroring the existing "develop new branch with checkout when local branch exists" case (lines 613-663), but return `"ref":{"name":"--orphan"}` from the `CreateLinkedBranch` mutation stub and set `opts.Checkout: true`. Register a `run.CommandStubber` expectation for `git checkout --orphan` (proving the raw flag is what gets executed) and assert that, absent a fix, the test passes with no rejection — then apply the fix and assert `developRun` returns `invalid branch name: "--orphan"` before any `cs.Register` command is invoked, matching the behavior already verified for `pr checkout` via the `strings.HasPrefix` guard.

### Citations

**File:** api/queries_branch_issue_reference.go (L79-87)
```go
	var branchNames []LinkedBranch

	for _, node := range query.Repository.Issue.LinkedBranches.Nodes {
		branch := LinkedBranch{
			BranchName: node.Ref.Name,
			URL:        fmt.Sprintf("%s/tree/%s", node.Ref.Repository.Url, node.Ref.Name),
		}
		branchNames = append(branchNames, branch)
	}
```

**File:** pkg/cmd/issue/develop/develop.go (L287-287)
```go
	return checkoutBranch(opts, branchRepo, branchName, worktreeTarget)
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

**File:** pkg/cmd/pr/checkout/checkout.go (L150-152)
```go
	if strings.HasPrefix(pr.HeadRefName, "-") {
		return fmt.Errorf("invalid branch name: %q", pr.HeadRefName)
	}
```

**File:** pkg/cmd/pr/checkout/checkout.go (L234-235)
```go
	case opts.GitClient.HasLocalBranch(context.Background(), localBranch):
		cmds = append(cmds, []string{"checkout", localBranch})
```
