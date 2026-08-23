### Title
Unsanitized branch names from `git branch -r --format` allow terminal escape-sequence injection into shell-completion output - ([File: git/client.go])

### Summary
`Client.TrackingBranchNames` in `git/client.go` returns raw branch names parsed from `git branch -r --list` output without any control-character sanitization, and these values are forwarded directly to Cobra's flag-completion callback in `pkg/cmdutil/flags.go`. An attacker who can get a victim to fetch a remote/fork containing a branch whose name embeds ANSI/terminal escape sequences can have those bytes echoed to the victim's terminal during shell tab-completion.

### Finding Description
`TrackingBranchNames` builds `git branch -r --format "%(refname:strip=3)" [--list */<escapeGlob(prefix)>*]`, runs it, and returns `strings.Split(string(output), "\n")` verbatim: [1](#0-0) 

`escapeGlob` only escapes glob metacharacters in the `prefix` argument (the text the *victim* is typing during completion) so that it is treated literally by `git branch --list`; it has no bearing on the actual branch *names* returned by `git`, which are attacker-controlled if the attacker created remote branches with unusual names (e.g. containing raw `\x1b` bytes — git permits most byte sequences in ref names).

The returned list is passed straight through to Cobra's completion function with no filtering: [2](#0-1) 

There is no stripping/escaping of non-printable or ANSI control bytes anywhere in this path. If the victim has previously added the attacker's fork/repo as a remote and fetched it (a very common workflow for `gh pr checkout` / reviewing forks), the malicious branch names become visible to `git branch -r` and thus to `TrackingBranchNames`, and will be printed by the shell as raw escape sequences when completion renders candidates.

### Impact Explanation
This is a terminal escape-sequence injection ("terminal spoofing") issue: crafted branch names could manipulate the victim's terminal display (e.g., overwrite prior output, hide/alter text, or attempt cursor tricks) when shell completion suggestions are rendered. It does not provide code execution, credential exfiltration, or file write — it is limited to terminal UI spoofing via the completion display, which is a low-severity class typically outside GitHub's bug bounty scope for remote code execution/credential disclosure, but matches the "terminal spoofing via completion UI" impact explicitly scoped in this question.

### Likelihood Explanation
Requires the victim to (1) have added/fetched an attacker-controlled remote containing branches with escape-sequence names, and (2) invoke shell completion (e.g., pressing Tab) on a `gh` command using a branch-name flag while that remote's branches are present. This is a plausible but non-trivial precondition — it depends on local victim action (fetching + completion), not simply running an ordinary `gh` command against attacker content.

### Recommendation
Sanitize/strip non-printable and ANSI control characters (e.g., `\x1b`, other C0 control bytes) from branch names returned by `TrackingBranchNames` before they are handed to `cobra.RegisterFlagCompletionFunc`, or filter/quote such names generically in the shared completion helper.

### Proof of Concept
Using the existing git-stub test harness for `git/client.go`:
1. Stub `git branch -r --format ...` to return a line containing `\x1b[2K\x1b[1Gmalicious` embedded in an otherwise valid branch name.
2. Call `client.TrackingBranchNames(ctx, "")` and assert the returned slice still contains the raw `\x1b` bytes (demonstrating no sanitization occurs).
3. Extend to `pkg/cmdutil/flags_test.go`: register `RegisterBranchCompletionFlags` with a fake `gitClient` whose `TrackingBranchNames` returns the crafted name, invoke the registered completion func, and assert the returned `[]string` contains unescaped control bytes — expected fix would have these stripped/escaped before being returned to Cobra.

### Citations

**File:** git/client.go (L698-712)
```go
func (c *Client) TrackingBranchNames(ctx context.Context, prefix string) []string {
	args := []string{"branch", "-r", "--format", "%(refname:strip=3)"}
	if prefix != "" {
		args = append(args, "--list", fmt.Sprintf("*/%s*", escapeGlob(prefix)))
	}
	cmd, err := c.Command(ctx, args...)
	if err != nil {
		return nil
	}
	output, err := cmd.Output()
	if err != nil {
		return nil
	}
	return strings.Split(string(output), "\n")
}
```

**File:** pkg/cmdutil/flags.go (L53-66)
```go
func RegisterBranchCompletionFlags(gitc gitClient, cmd *cobra.Command, flags ...string) error {
	for _, flag := range flags {
		err := cmd.RegisterFlagCompletionFunc(flag, func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if repoFlag := cmd.Flag("repo"); repoFlag != nil && repoFlag.Changed {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return gitc.TrackingBranchNames(context.TODO(), toComplete), cobra.ShellCompDirectiveNoFileComp
		})
		if err != nil {
			return err
		}
	}
	return nil
}
```
