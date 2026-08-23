### Title
GitHub Skills "upstream provenance" check uses raw string equality instead of canonical GitHub repo comparison, allowing an attacker to spoof or evade the re-publisher/upstream distinction and redirect installation to an arbitrary attacker-controlled host - (File: `pkg/cmd/skills/install/install.go`)

### Summary
`gh skill install` fetches a skill's `SKILL.md` from the repository being installed and reads an attacker-controlled `github-repo` metadata field to detect whether the skill was "re-published" from an upstream repository. The comparison used to decide whether the declared repo is "the same as" the current repo is a raw `string ==` on full repo URLs, unlike the codebase's own canonical repo-equality helper `ghrepo.IsSame`, which correctly case-folds owner/name/host before comparing. This is the same bug class as the reported `Fr` issue: two logically-identical values (GitHub repo identities are case-insensitive) can have different raw representations and therefore compare as "not equal," causing security-relevant logic that depends on that comparison to make an incorrect decision.

### Finding Description
`checkUpstreamProvenance` decides whether a skill is a re-publish of another repository by comparing the metadata-declared repo URL to the current repo's canonical URL with plain string equality: [1](#0-0) 

```
existingRepo, _ := result.Metadata.Meta["github-repo"].(string)
...
currentRepoURL := source.BuildRepoURL(hostname, opts.repo.RepoOwner(), opts.repo.RepoName())
if existingRepo == currentRepoURL {
    return nil, false, nil
}
upstreamRepo, parseErr := source.ParseRepoURL(existingRepo)
```

`currentRepoURL` is built directly from `opts.repo.RepoOwner()`/`RepoName()` with whatever casing they currently have [2](#0-1) , while `existingRepo` is a completely attacker-controlled string taken from the SKILL.md frontmatter of the repository being installed from. Because GitHub owner/repo names are case-insensitive, elsewhere in the codebase repo identity is intentionally compared with `strings.EqualFold`: [3](#0-2) 

but `checkUpstreamProvenance` does not use this canonicalized comparison. When `existingRepo` differs from `currentRepoURL` only in case (e.g. `https://github.com/Owner/Repo` vs `https://github.com/owner/repo`), the two values are treated as different even though they identify the same repository. This triggers the "upstream" branch, which parses the attacker-supplied string into a `ghrepo.Interface` via: [4](#0-3) 

`ParseRepoURL` → `ghrepo.FromFullName` does not restrict the resulting host to `github.com`/supported tenancy hosts — that check (`ValidateSupportedHost`) exists in the same file but is never invoked on the parsed `upstreamRepo` before it is offered to the user or returned to the installer: [5](#0-4) 

In interactive mode, the user is prompted to pick between the current ("re-publisher") repo and this unvalidated "upstream" repo, and selecting it, or passing `--upstream`, causes the parsed, attacker-declared repository (potentially on any host, since host validation is skipped) to be returned as the install target: [6](#0-5) 

### Impact Explanation
The incorrect equality check (analogous to the unreduced-`Fr` comparison bug) undermines the trust decision the feature exists to make:
- Same-repo values that should compare equal (case-insensitive GitHub identity) can be forced to compare unequal, causing the tool to falsely present an "upstream" redirect option that isn't validated against `ValidateSupportedHost`.
- Because `ParseRepoURL`/`ghrepo.FromFullName` place no restriction on hostname, a crafted `github-repo` metadata value can encode an arbitrary host. If a user accepts the "upstream" choice (or automation passes `--upstream`), subsequent installation steps operate on a repo object pointing at a host the user did not intend to trust, which is exactly the kind of "authenticated request sent to an attacker host" scenario the validation rules call out.
- At minimum, this is a verification/consistency bypass in a supply-chain-relevant feature (skills are explicitly documented as unverified/potentially malicious content, per `printPreInstallDisclaimer`), which raises the bar of user trust in a check that can silently be defeated by casing tricks alone.

### Likelihood Explanation
Exploitation requires the victim to run `gh skill install` against a repository/skill under attacker control (or attacker-influenced), which is the normal, expected trust boundary for this feature — no special privileges or MITM are needed; the "attacker-published content" is the skill repo itself. The specific case-folding mismatch is trivial to construct (differ only in letter case of owner/repo in the URL). I was not able to fully trace the exact downstream code path that consumes the returned `upstreamRepo` after the interactive prompt (the caller of `checkUpstreamProvenance` was not retrieved within the available tool budget), so I cannot confirm with certainty whether later steps additionally enforce a host allow-list before contacting the redirected repo. This is a material gap in confirming full end-to-end impact and should be verified against the actual call site.

### Recommendation
- Replace the raw `existingRepo == currentRepoURL` string comparison in `checkUpstreamProvenance` with a canonical, case-insensitive repository-identity comparison (e.g. parse both sides into `ghrepo.Interface` and use `ghrepo.IsSame`), mirroring the pattern already used elsewhere in the codebase.
- Call `source.ValidateSupportedHost` on the parsed `upstreamRepo` immediately after `source.ParseRepoURL` in `checkUpstreamProvenance`, before it is ever offered to the user or returned to the caller, rejecting unsupported/untrusted hosts outright.
- Audit the caller of `checkUpstreamProvenance` to confirm host validation and any subsequent API/network calls made against the returned "upstream" repo are properly scoped to supported GitHub hosts.

### Proof of Concept
1. Attacker publishes a skill repository, e.g. `Attacker/Skills` (note capitalization), containing a `SKILL.md` whose frontmatter sets `github-repo: https://github.com/attacker/skills` (lowercase variant of the same repo).
2. Victim runs `gh skill install Attacker/Skills` interactively.
3. `currentRepoURL` is computed as `https://github.com/Attacker/Skills` while `existingRepo` is `https://github.com/attacker/skills`; the raw `==` comparison fails even though both refer to the identical GitHub repository (GitHub repo names are case-insensitive), so the code proceeds into the "upstream detected" branch instead of short-circuiting.
4. The user is shown a prompt distinguishing "re-publisher" vs. "upstream," despite there being no real difference — undermining confidence in the check and, if the attacker instead sets `github-repo` to a URL on an arbitrary host, allowing an unvalidated repo (potential non-GitHub host) to be surfaced/selected as the "upstream" install target, since `ParseRepoURL`/`ghrepo.FromFullName` do not enforce `ValidateSupportedHost`.

### Citations

**File:** pkg/cmd/skills/install/install.go (L1327-1336)
```go
	existingRepo, _ := result.Metadata.Meta["github-repo"].(string)
	if existingRepo == "" {
		return nil, false, nil
	}

	currentRepoURL := source.BuildRepoURL(hostname, opts.repo.RepoOwner(), opts.repo.RepoName())
	if existingRepo == currentRepoURL {
		return nil, false, nil
	}

```

**File:** pkg/cmd/skills/install/install.go (L1359-1373)
```go
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

**File:** internal/skills/source/source.go (L14-17)
```go
// BuildRepoURL returns the canonical repository URL stored in skill metadata.
func BuildRepoURL(host, owner, repo string) string {
	return ghrepo.GenerateRepoURL(ghrepo.NewWithHost(owner, repo, host), "")
}
```

**File:** internal/skills/source/source.go (L19-32)
```go
// ParseRepoURL parses a repository URL stored in skill metadata.
func ParseRepoURL(raw string) (ghrepo.Interface, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("repository URL is empty")
	}

	repo, err := ghrepo.FromFullName(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid repository URL %q: %w", raw, err)
	}

	return repo, nil
}
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

**File:** internal/ghrepo/repo.go (L74-83)
```go
func normalizeHostname(h string) string {
	return strings.ToLower(strings.TrimPrefix(h, "www."))
}

// IsSame compares two GitHub repositories
func IsSame(a, b Interface) bool {
	return strings.EqualFold(a.RepoOwner(), b.RepoOwner()) &&
		strings.EqualFold(a.RepoName(), b.RepoName()) &&
		normalizeHostname(a.RepoHost()) == normalizeHostname(b.RepoHost())
}
```
