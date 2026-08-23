## Analysis

The HoneyLocker bug is a **trust-without-cross-verification** pattern: an authorization decision (migrate) is made using one signal (codehash) while a related, security-critical property (the destination's initialized state) is never independently verified, letting the destination assert whatever values it wants.

The closest reachable analog in `gh` is in the `gh skill install` upstream-provenance redirect, where the *target repository of a trust redirect* is taken directly from attacker-controlled content inside the very artifact being installed, with no independent corroboration.

### Title
Skill install `--upstream` redirect trusts attacker-supplied `github-repo` metadata with no provenance verification - (File: pkg/cmd/skills/install/install.go)

### Summary
`gh skill install` detects "republished" skills by reading a `github-repo` key from the installed skill's own front-matter, and if `--upstream` is passed, unconditionally redirects installation to that self-declared repository and re-runs the install pipeline against it.

### Finding Description
`checkUpstreamProvenance` fetches the candidate skill's `SKILL.md`, parses its front-matter, and reads an attacker-controlled `github-repo` field [1](#0-0) . If that value differs from the repo the user actually specified, and `--upstream` was passed, the code redirects immediately — before any interactive confirmation and even in non-interactive/CI contexts: [2](#0-1) 

There is no check that the "upstream" repo is actually related to the source repo (no ownership check, no cross-signing, no confirmation the two repos share history/maintainers) — the redirect target is entirely a string embedded by whoever authored the front-matter of the currently-installed repo. This mirrors the HoneyLocker flaw: the tool grants elevated trust (treating the target as "the canonical/legitimate source") based purely on a single self-reported value, without validating any correlated property that would actually establish that relationship.

The recursive call `return installRun(opts)` [3](#0-2)  then fetches and writes files from the attacker-chosen repository to disk, labeling them "from {upstream}" in the install output, which spoofs the provenance the user believes they are trusting when using `--upstream` to avoid a "republisher."

### Impact Explanation
An attacker who publishes a skill repository can embed a `github-repo` metadata value pointing to a second, entirely unrelated attacker-controlled repository. Any user who follows the tool's own recommended precaution (`--upstream`, described in the CLI's own warning text as pointing to "the original source") will have `gh` silently fetch and write content from a different, unverified attacker-controlled repository to disk, while displaying a repo label that falsely implies legitimacy/provenance. This is a verification-bypass class issue: the "upstream" trust signal is unauthenticated data supplied by the same party being evaluated.

### Likelihood Explanation
Reachable by any remote, unprivileged party who can publish a public GitHub repo with skill content — no special access is required. Exploitation requires the victim to use `--upstream` (a flag the tool itself surfaces to route around "re-publishers"), which is a plausible, security-motivated user action rather than an edge case.

### Recommendation
Do not trust the self-declared `github-repo` field as sufficient to redirect installation. At minimum, require explicit interactive confirmation showing the exact target org/repo even when `--upstream` is set (do not bypass the prompt), and consider requiring some independent corroboration (e.g., the "upstream" repo being an ancestor via fork relationship, or matching a maintainer-controlled registry) before treating it as canonical.

### Proof of Concept
1. Attacker creates `attacker/republished-skills` containing a skill whose `SKILL.md` front-matter sets `github-repo: https://github.com/attacker/evil-upstream`.
2. Victim runs `gh skill install attacker/republished-skills --upstream` (following the tool's own guidance to prefer canonical sources).
3. `checkUpstreamProvenance` reads the attacker-supplied `github-repo` value [4](#0-3)  and, because `opts.Upstream` is true, immediately redirects and reinstalls from `attacker/evil-upstream` [5](#0-4)  with no further validation that the two repos are related, writing that repo's content to disk under a label implying it is the legitimate upstream source.

### Citations

**File:** pkg/cmd/skills/install/install.go (L364-368)
```go
			opts.repo = upstreamRepo
			opts.SkillSource = ghrepo.FullName(upstreamRepo)
			opts.version = ""
			opts.Pin = ""
			return installRun(opts)
```

**File:** pkg/cmd/skills/install/install.go (L1319-1336)
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

```

**File:** pkg/cmd/skills/install/install.go (L1349-1357)
```go
	if opts.Upstream {
		fmt.Fprintf(opts.IO.ErrOut, "Redirecting install to %s...\n", upstreamLabel)
		return upstreamRepo, true, nil
	}

	if !opts.IO.CanPrompt() {
		fmt.Fprintf(opts.IO.ErrOut, "  Installing from %s (use --upstream or interactive mode to choose upstream)\n", repoSource)
		return nil, true, nil
	}
```
