### Title
`gh skill update` re-downloads and installs skill content without the unverified-content warning shown by `gh skill install` - (File: pkg/cmd/skills/update/update.go)

### Summary
The NFTX report flags `swapTo()` for combining the transfer logic of `mintTo()`/`redeemTo()` while skipping the safety checks (`allValidNFTs`, `afterRedeemHook`) that those individual entry points enforce. The same "combined-operation skips a sibling's safety gate" pattern exists in `gh skill update`: it re-implements the download/write path of `gh skill install` via `installer.Install` directly, but never calls the disclaimer/review-hint logic that `install` uses to warn the user before executing or trusting fetched skill content.

### Finding Description
`gh skill install` treats installed skill content as untrusted and unverified. Before/around installing, it explicitly warns the user via `printPreInstallDisclaimer` and `printReviewHint`: [1](#0-0) [2](#0-1) 

These calls exist specifically because skill content (e.g. `SKILL.md`, associated scripts) is unverified and "may contain prompt injections, hidden instructions, or malicious scripts."

`gh skill update`, however, has its own independent code path (`updateRun` → `updateSkillInPlace`) that fetches remote skill content and writes it to disk by calling `installer.Install` directly, bypassing the `pkg/cmd/skills/install` command entirely: [3](#0-2) 

Nowhere in `update.go` is `printPreInstallDisclaimer` or `printReviewHint` (or any equivalent warning) invoked — confirmed by searching the file for `Disclaimer`, `ReviewHint`, `not verified`, and `prompt injection`, all of which appear only in `install.go`/`install_test.go`. The `update` flow only prints generic "Updated" success messages and update-availability listings: [4](#0-3) 

This mirrors the NFTX bug precisely: `swapTo` reused `receiveNFTs`/`withdrawNFTsTo` (the mechanics of `mintTo`/`redeemTo`) but dropped the `allValidNFTs`/`afterRedeemHook` checks that made those individual paths safe. Here, `update` reuses `installer.Install` (the mechanics of `install`) but drops the disclaimer/review-hint logic that made the `install` command's UX safe.

### Impact Explanation
A user who trusts `gh skill install`'s warning UX (and therefore reviews skill content before running/trusting it, per the disclaimer) may reasonably assume the same protection applies to `gh skill update`. Because `update` silently re-fetches and overwrites skill files — including with `--force`, which explicitly rewrites locally modified content — without ever surfacing the "not verified by GitHub … may contain prompt injections, hidden instructions, or malicious scripts" warning or the "review before use" hint pointing to `gh skill preview`, a user (or an automated agent invoking `gh skill update --all`) can end up with newly modified, unreviewed, potentially malicious skill content silently installed and available for execution by the agent host, without any of the safeguards the `install` path deliberately provides.

### Likelihood Explanation
`gh skill update` (and `--all`/`--force` non-interactive variants, which are explicitly documented as suitable for scripted/automated use) is a normal, expected command in everyday workflows — no attacker-controlled host or MITM is required beyond the already-existing threat model of an untrusted skill repository publishing new/malicious content at the next update check. This is a straightforward reachable path during normal `gh` usage, not a contrived or privileged scenario.

### Recommendation
Route `gh skill update`'s in-place update path through the same disclaimer/review-hint logic used by `gh skill install` (e.g., factor `printPreInstallDisclaimer`/`printReviewHint` into a shared helper called from both `install.go`'s `installRun` and `update.go`'s `updateRun`/`updateSkillInPlace`), so that any code path that writes fetched, unverified skill content to disk consistently warns the user and directs them to review the content (ideally referencing the new tree SHA) before it takes effect.

### Proof of Concept
1. Install a skill normally: `gh skill install owner/repo skill-name` — observe the "not verified by GitHub … Always review skill contents before use" disclaimer and the `gh skill preview owner/repo skill-name@sha` review hint, per `install.go`'s `printPreInstallDisclaimer`/`printReviewHint`.
2. Have the upstream skill repository push a new commit changing `SKILL.md` or an associated script to include malicious instructions/content.
3. Run `gh skill update --all` (or `gh skill update --force --all`, common in scripts/CI or agent automation).
4. Observe that `updateRun`/`updateSkillInPlace` (`pkg/cmd/skills/update/update.go:418-461`) downloads and installs the new content via `installer.Install`, printing only `"Updated <name>"`, with none of the unverified-content warnings or preview hints shown by `install`, despite the update overwriting the on-disk skill content that an agent host may subsequently load and execute.

### Citations

**File:** pkg/cmd/skills/install/install.go (L1187-1191)
```go
// printPreInstallDisclaimer prints a warning that installed skills are unverified
// and should be inspected before use.
func printPreInstallDisclaimer(w io.Writer, cs *iostreams.ColorScheme) {
	fmt.Fprintf(w, "\n%s Skills are not verified by GitHub and may contain prompt injections, hidden instructions, or malicious scripts. Always review skill contents before use.\n\n", cs.WarningIcon())
}
```

**File:** pkg/cmd/skills/install/install.go (L1198-1206)
```go
func printReviewHint(w io.Writer, cs *iostreams.ColorScheme, repo, sha string, skillNames []string, allowHiddenDirs bool) {
	if len(skillNames) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%s Skills may contain prompt injections or malicious scripts.\n", cs.WarningIcon())
	if repo == "" {
		fmt.Fprintln(w, "  Review the installed files before use.")
		return
	}
```

**File:** pkg/cmd/skills/update/update.go (L386-398)
```go
	var failed bool
	for _, u := range updates {
		if err := updateSkillInPlace(opts, u, apiClient, gitRoot, homeDir); err != nil {
			fmt.Fprintf(opts.IO.ErrOut, "%s Failed to update %s: %v\n", cs.FailureIcon(), u.local.name, err)
			failed = true
			continue
		}
		if opts.IO.IsStdoutTTY() {
			fmt.Fprintf(opts.IO.Out, "%s Updated %s\n", cs.SuccessIcon(), u.local.name)
		} else {
			fmt.Fprintf(opts.IO.Out, "Updated %s\n", u.local.name)
		}
	}
```

**File:** pkg/cmd/skills/update/update.go (L418-461)
```go
func updateSkillInPlace(opts *UpdateOptions, u pendingUpdate, apiClient *api.Client, gitRoot, homeDir string) error {
	if u.local.dir == "" {
		return fmt.Errorf("cannot update %s: no install location recorded", u.local.name)
	}

	parent := filepath.Dir(u.local.dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("could not ensure parent directory %s: %w", parent, err)
	}

	// Stage as a sibling of the existing skill directory so the swap stays
	// on the same filesystem and every rename is atomic.
	staging, err := os.MkdirTemp(parent, "."+u.skill.Name+".gh-skill-update-")
	if err != nil {
		return fmt.Errorf("could not create staging directory: %w", err)
	}
	defer os.RemoveAll(staging)

	installOpts := &installer.Options{
		Host:    u.local.repoHost,
		Owner:   u.local.owner,
		Repo:    u.local.repo,
		Ref:     u.resolved.Ref,
		SHA:     u.resolved.SHA,
		Skills:  []discovery.Skill{u.skill},
		Dir:     staging,
		GitRoot: gitRoot,
		HomeDir: homeDir,
		Client:  apiClient,
	}
	if _, err := installer.Install(installOpts); err != nil {
		return err
	}

	stagedSkillDir := filepath.Join(staging, u.skill.Name)
	if _, err := os.Stat(stagedSkillDir); err != nil {
		return fmt.Errorf("installer did not produce %s: %w", stagedSkillDir, err)
	}

	if err := os.MkdirAll(u.local.dir, 0o755); err != nil {
		return fmt.Errorf("could not ensure skill directory %s: %w", u.local.dir, err)
	}

	return swapDirectoryContents(u.local.dir, stagedSkillDir)
```
