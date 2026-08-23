### Title
Missing leading-dash validation on attacker-controlled linked-branch name enables git argument injection in `issue develop --checkout` - ([File: pkg/cmd/issue/develop/develop.go])

### Summary
`checkoutBranch` in `pkg/cmd/issue/develop/develop.go` passes the linked-branch name returned by GitHub's linked-branch API directly as a bare positional argument to `git checkout <branch>` and `git pull ... <branch>`, without checking for a leading `-`. The sibling command `pkg/cmd/pr/checkout/checkout.go` already guards against exactly this attack by rejecting branch names starting with `-` [1](#0-0) , confirming this is a recognized, previously-fixed vulnerability class that was not applied to `issue develop`.

### Finding Description
In `checkoutBranch`, the API-returned `checkoutBranch` string is used unsanitized in multiple git invocations: [2](#0-1) 

`gc.CheckoutBranch` builds `args := []string{"checkout", branch}` [3](#0-2)  and `gc.Pull` builds `args := []string{"pull", "--ff-only", remote, branch}` [4](#0-3) , both passing the attacker-influenced name as a bare, unescaped, non-`--`-delimited token. Git's option parser scans all argv tokens for a leading `-`/`--` regardless of position (unless a `--` separator is used), so a branch name beginning with `-` is interpreted as a flag to `git checkout`/`git pull` rather than a ref name.

The value originates from `branchName`, which can come from `findExistingLinkedBranchName`, itself populated by `api.ListLinkedBranches` reading `branch.BranchName` straight from the GitHub GraphQL response for the issue's linked branches [5](#0-4) . Because git ref names are permitted to begin with `-` at the protocol level (only local `git branch` CLI defensively rejects this), an attacker who controls a repository (their own repo, where they can link a branch to an issue and push/create a ref via API/git-protocol rather than `git branch`) can supply a branch name like `-o` or `--upload-pack=...`-style names that begin with `-`. When a victim later runs `gh issue develop <attacker-issue-url> --checkout`, this crafted name reaches `gc.CheckoutBranch`/`gc.Pull` unguarded.

Note: `gc.Fetch`'s refspec is wrapped as `+refs/heads/%s:refs/remotes/%s/%s`, so the resulting argument always starts with `+`, not `-`, and is not exploitable this way. `gc.CheckoutNewBranch` places `branch` immediately after the value-consuming `-b` flag, so it is also not directly injectable. The exposed paths are specifically `gc.CheckoutBranch` (existing-local-branch case) and the subsequent `gc.Pull` calls.

### Impact Explanation
This allows an attacker-controlled string to be interpreted as a git command-line option rather than a ref name, which is the same argument-injection class GitHub's own `pr checkout` command explicitly hardened against [1](#0-0) . Depending on which git option collides with the crafted string, this can cause unexpected git behavior (denial of local repository state, unexpected checkout/pull semantics) on the victim's machine triggered purely by attacker-controlled repo content, matching a local command/argument-injection impact class.

### Likelihood Explanation
Requires only that the attacker control a repository/issue where they can create a linked branch with a crafted ref name (their own repo), and that a victim later runs `gh issue develop <url> --checkout` against it — no elevated privileges, tokens, or MITM needed. This matches the "unprivileged remote attacker publishes content victim later interacts with" threat model.

### Recommendation
Add the same guard used in `pr checkout` before using the branch name in any git invocation in `develop.go`'s `checkoutBranch`:
```go
if strings.HasPrefix(checkoutBranch, "-") {
    return fmt.Errorf("invalid branch name: %q", checkoutBranch)
}
```
placed immediately after `branchName`/`checkoutBranch` is determined and before any `gc.Fetch`, `gc.CheckoutBranch`, `gc.CheckoutNewBranch`, or `gc.Pull` call.

### Proof of Concept
```go
func TestDevelop_CheckoutBranch_RejectsLeadingDash(t *testing.T) {
    // Simulate api.ListLinkedBranches returning BranchName: "-x" via httpmock
    // for a linked branch query on the attacker's issue.
    http := &httpmock.Registry{}
    defer http.Verify(t)
    http.Register(
        httpmock.GraphQL(`query IssueLinkedBranches\b`),
        httpmock.StringResponse(`{"data":{"repository":{"issue":{"linkedBranches":{"nodes":[
            {"ref":{"name":"-x"},"id":"LB_1"}
        ]}}}}}`),
    )

    cs, cmdTeardown := run.Stub()
    defer cmdTeardown(t)
    // Expect no git invocation to receive "-x" as a bare positional arg;
    // instead expect an "invalid branch name" error before any git command runs.

    opts := &DevelopOptions{
        Checkout: true,
        Name:     "-x",
        // ... wire up GitClient, Remotes, BaseRepo, HttpClient as in existing develop tests
    }
    err := developRun(opts)
    assert.EqualError(t, err, `invalid branch name: "-x"`)
    cs.Verify(t) // no git checkout/pull commands should have been registered/consumed
}
```
Expected current (vulnerable) behavior: no such validation exists, so `gc.CheckoutBranch`/`gc.Pull` would be invoked with `"-x"` as a bare argument; the fix should make this test pass by rejecting the name before any git command executes.

### Citations

**File:** pkg/cmd/pr/checkout/checkout.go (L150-152)
```go
	if strings.HasPrefix(pr.HeadRefName, "-") {
		return fmt.Errorf("invalid branch name: %q", pr.HeadRefName)
	}
```

**File:** pkg/cmd/issue/develop/develop.go (L290-304)
```go
func findExistingLinkedBranchName(branches []api.LinkedBranch, branchRepo ghrepo.Interface, branchName string) string {
	for _, branch := range branches {
		if branch.BranchName != branchName {
			continue
		}
		linkedRepo, err := linkedBranchRepoFromURL(branch.URL)
		if err != nil {
			continue
		}
		if ghrepo.IsSame(linkedRepo, branchRepo) {
			return branch.BranchName
		}
	}
	return ""
}
```

**File:** pkg/cmd/issue/develop/develop.go (L405-412)
```go
	if gc.HasLocalBranch(ctx.Background(), checkoutBranch) {
		if err := gc.CheckoutBranch(ctx.Background(), checkoutBranch); err != nil {
			return err
		}

		if err := gc.Pull(ctx.Background(), baseRemote.Name, checkoutBranch); err != nil {
			_, _ = fmt.Fprintf(opts.IO.ErrOut, "%s warning: not possible to fast-forward to: %q\n", opts.IO.ColorScheme().WarningIcon(), checkoutBranch)
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

**File:** git/client.go (L881-894)
```go
func (c *Client) Pull(ctx context.Context, remote, branch string, mods ...CommandModifier) error {
	args := []string{"pull", "--ff-only"}
	if remote != "" && branch != "" {
		args = append(args, remote, branch)
	}
	cmd, err := c.AuthenticatedCommand(ctx, AllMatchingCredentialsPattern, args...)
	if err != nil {
		return err
	}
	for _, mod := range mods {
		mod(cmd)
	}
	return cmd.Run()
}
```
