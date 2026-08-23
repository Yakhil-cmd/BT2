### Title
Skill Install Blindly Redirects to Attacker-Specified Repository via Unverified Frontmatter Metadata - ([File: pkg/cmd/skills/install/install.go])

### Summary
`gh skill install` includes an "upstream provenance" feature intended to detect when an installed skill was copied ("re-published") from another repository and redirect the install to the original source. The redirect target, however, is taken verbatim from a `github-repo:` field inside the **SKILL.md frontmatter of the very (untrusted) repository the user is installing from**. Nothing verifies that this claimed "upstream" repository is actually the true origin of the skill — an attacker publishing a malicious skill can set this field to any `owner/repo` string of their choosing. This mirrors the reported Solana bug class: a critical trust decision (which token vault/authority governs funds; here, which repository governs the installed skill's actual source) is derived entirely from attacker-controlled, unvalidated input.

### Finding Description
`checkUpstreamProvenance` fetches `SKILL.md` from the repository the user is installing from and parses its YAML frontmatter for a `metadata.github-repo` field: [1](#0-0) 

If this field differs from the current repo URL, the code treats it as proof the skill was "re-published" from that other repository and offers (or, with `--upstream`, automatically performs) a redirect that swaps `opts.repo` to the attacker-declared repository and recursively re-runs the entire install flow against it: [2](#0-1) [3](#0-2) 

The only validation performed on the redirect target is `source.ValidateSupportedHost`, which merely checks that the host is `github.com` or a supported tenancy — it does not verify that the claimed repository has any real relationship to the skill being installed: [4](#0-3) 

Because the `github-repo` value originates from content the attacker fully controls (their own published `SKILL.md`), the "upstream" is effectively a self-declared, unverified claim — analogous to trusting a token mint's self-reported authority/extension state without checking whether it actually holds the invariant the protocol depends on.

### Impact Explanation
- With `--upstream` (documented as "install from upstream when a re-published skill is detected") used non-interactively (e.g., in CI/automation, or by an AI agent invoking `gh skill install` on its own per `skills/gh-skill/SKILL.md`), the tool silently discards the user/agent-specified repository and instead fetches and writes files from an arbitrary attacker-chosen repository, then injects tracking metadata (`github-repo`, `github-tree-sha`, etc.) claiming that repository as the legitimate source.
- Even interactively, the misleading provenance message ("This skill was originally published in `X`") gives a false sense of legitimacy for a target repository the attacker fully controls, increasing the chance a user selects "upstream" and installs attacker-authored files (which downstream agents such as Copilot/Claude Code will read and act on) instead of the source they intended to vet.
- The written files land under the normal skill install directory (no path-traversal — that is separately guarded by `safepaths`), but the *content provenance guarantee* that the "upstream detection" feature is supposed to provide is bypassed, since the check trusts data supplied by the same untrusted party it is meant to validate.

### Likelihood Explanation
Any GitHub user can publish a public repository containing a `SKILL.md` with a crafted `metadata.github-repo` field pointing to a second repository they also control (or to any arbitrary `owner/repo`). No special privileges are required, and the flow is fully reachable through the documented, supported `gh skill install <owner>/<repo> <skill>[--upstream]` command described in `skills/gh-skill/SKILL.md`, including when driven by an autonomous agent.

### Recommendation
- Do not automatically redirect installs based on self-declared `github-repo` metadata from an untrusted, attacker-controlled repository; treat it purely as an informational hint.
- If an "install from upstream" feature is retained, require independent corroboration (e.g., cross-check that the target repository actually references/forks/links back to the re-publisher, or require explicit user confirmation naming the exact target every time, even under `--upstream`) before switching the install source.
- Clearly warn that the claimed "upstream" is unverified and attacker-controllable whenever it differs from the user-supplied `SkillSource`.

### Proof of Concept
1. Attacker creates two public repositories: `attacker/decoy-skills` (visible as the install target) and `attacker/payload-skills` (contains the real malicious skill content).
2. In `attacker/decoy-skills`, publish `skills/git-commit/SKILL.md` with frontmatter:
   ```yaml
   ---
   name: git-commit
   description: Writes commits
   metadata:
     github-repo: https://github.com/attacker/payload-skills
     github-tree-sha: <sha>
   ---
   ```
3. Victim (or an automation script/agent) runs:
   ```
   gh skill install attacker/decoy-skills git-commit --upstream
   ```
4. `checkUpstreamProvenance` parses the attacker-controlled frontmatter, treats `attacker/payload-skills` as the "upstream," and `installRun` recurses with `opts.repo` set to `attacker/payload-skills`, silently installing content from a repository the user never named on the command line — see the redirect logic at [5](#0-4) .

### Citations

**File:** pkg/cmd/skills/install/install.go (L345-369)
```go
	if len(selectedSkills) == 1 && selectedSkills[0].BlobSHA != "" {
		upstreamRepo, detected, err := checkUpstreamProvenance(opts, apiClient, hostname, selectedSkills[0], resolved.SHA)
		if err != nil {
			return err
		}
		if upstreamRepo != nil {
			redirectDims := map[string]string{}
			select {
			case r := <-visCh:
				if r.err == nil && r.vis == discovery.RepoVisibilityPublic {
					redirectDims["from_owner"] = visOwner
					redirectDims["from_repo"] = visRepo
				}
			case <-time.After(visibilityWaitTimeout):
			}
			opts.Telemetry.Record(ghtelemetry.Event{
				Type:       "skill_upstream_redirect",
				Dimensions: redirectDims,
			})
			opts.repo = upstreamRepo
			opts.SkillSource = ghrepo.FullName(upstreamRepo)
			opts.version = ""
			opts.Pin = ""
			return installRun(opts)
		}
```

**File:** pkg/cmd/skills/install/install.go (L1319-1337)
```go
	content := string(decoded)

	result, parseErr := frontmatter.Parse(content)
	if parseErr != nil || result.Metadata.Meta == nil {
		//nolint:nilerr // unparsable frontmatter means no upstream to detect
		return nil, false, nil
	}

	existingRepo, _ := result.Metadata.Meta["github-repo"].(string)
	if existingRepo == "" {
		return nil, false, nil
	}

	currentRepoURL := source.BuildRepoURL(hostname, opts.repo.RepoOwner(), opts.repo.RepoName())
	if existingRepo == currentRepoURL {
		return nil, false, nil
	}

	upstreamRepo, parseErr := source.ParseRepoURL(existingRepo)
```

**File:** pkg/cmd/skills/install/install.go (L1343-1373)
```go
	cs := opts.IO.ColorScheme()
	upstreamLabel := ghrepo.FullName(upstreamRepo)
	repoSource := ghrepo.FullName(opts.repo)

	fmt.Fprintf(opts.IO.ErrOut, "%s This skill was originally published in %s\n", cs.WarningIcon(), upstreamLabel)

	if opts.Upstream {
		fmt.Fprintf(opts.IO.ErrOut, "Redirecting install to %s...\n", upstreamLabel)
		return upstreamRepo, true, nil
	}

	if !opts.IO.CanPrompt() {
		fmt.Fprintf(opts.IO.ErrOut, "  Installing from %s (use --upstream or interactive mode to choose upstream)\n", repoSource)
		return nil, true, nil
	}

	choices := []string{
		fmt.Sprintf("%s (re-publisher, recommended)", repoSource),
		fmt.Sprintf("%s (upstream)", upstreamLabel),
	}
	idx, err := opts.Prompter.Select("Install from:", "", choices)
	if err != nil {
		return nil, true, err
	}

	if idx == 1 {
		fmt.Fprintf(opts.IO.ErrOut, "Redirecting install to %s...\n", upstreamLabel)
		return upstreamRepo, true, nil
	}

	return nil, true, nil
```

**File:** internal/skills/source/source.go (L53-68)
```go
// ValidateSupportedHost rejects hosts that are not supported.
// Supported hosts are github.com and GHEC with data residency (*.ghe.com).
// GitHub Enterprise Server is not currently supported.
func ValidateSupportedHost(host string) error {
	host = normalizeHost(host)
	if host == "" {
		return fmt.Errorf("could not determine repository host")
	}
	if host == SupportedHost || ghauth.IsTenancy(host) {
		return nil
	}
	if ghauth.IsEnterprise(host) {
		return fmt.Errorf("GitHub Skills does not currently support GitHub Enterprise Server; got %s", host)
	}
	return fmt.Errorf("unsupported host for GitHub Skills: %s", host)
}
```
