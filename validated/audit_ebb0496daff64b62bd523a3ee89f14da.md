### Title
Unverified attacker-controlled "upstream" redirect metadata in `gh skill install` leads to installing skill content from an attacker-chosen repository - (File: pkg/cmd/skills/install/install.go)

### Summary
The Uniswap report describes a class of bug where an attacker-controlled "path" parameter (the middle hop of a multi-step operation) is blindly trusted by the system and used to redirect execution, causing a victim to unknowingly interact with attacker-controlled content instead of the intended target. The closest reachable analog in `gh` is the `gh skill install` "upstream provenance" redirect: the CLI reads a `github-repo` field from a skill's own `SKILL.md` frontmatter — content that is entirely authored by whoever published the repository the user is installing from — and uses that value to redirect the installation source to a different repository, with no cryptographic or ownership verification tying the two together.

### Finding Description
`checkUpstreamProvenance` fetches the target skill's `SKILL.md` via the contents API and parses its frontmatter for a `github-repo` key: [1](#0-0) 

The value is parsed with `source.ParseRepoURL`, which merely calls `ghrepo.FromFullName` — there is no validation that the "re-publisher" repository (the one the user actually pointed `gh skill install` at) has any real relationship to the claimed "upstream" repository: [2](#0-1) 

If a redirect is detected, the CLI either:
- silently prefers the re-publisher by default in non-interactive mode, or
- automatically switches to the "upstream" repo when `--upstream` is passed, or
- offers the attacker-labeled "upstream" as a selectable, seemingly-authoritative option in interactive mode: [3](#0-2) 

Back in `installRun`, once the upstream repo is chosen, the CLI recurses with `opts.repo` swapped to the attacker-declared repository and re-runs discovery/installation against it: [4](#0-3) 

Because `github-repo` is just a string embedded by whoever controls the visible/published repository, any attacker publishing a skill repo (the "re-publisher") can set this metadata field to point to an entirely different, attacker-controlled repository and have it presented to victims as the trustworthy "original" source — the exact same trust pattern as the Uniswap bug, where an attacker-controlled intermediate value (the swap path's middle hop) is accepted and acted upon without independent verification of legitimacy. The only server-side constraint is `source.ValidateSupportedHost`, which restricts the *host* to `github.com`/GHEC tenancy, but places no constraint on *which* repo on that host is used: [5](#0-4) 

### Impact Explanation
A user who runs `gh skill install <attacker-controlled-repo>` (e.g., because it looked legitimate, ranked well, or was recommended) can be steered by the repo owner's self-declared metadata into installing skill files from a second, also attacker-chosen, repository — either automatically (`--upstream`) or via a UI element that frames the attacker's chosen repo as "upstream (recommended)". Since installed skills are files later consumed by AI coding agents (per the Agent Skills System), this can result in unintended/malicious skill content being written to disk and later executed/interpreted by an agent, i.e., an unprivileged remote attacker steering file installation/content sourcing away from the location the victim intended, analogous to the financial redirection in the underlying report.

### Likelihood Explanation
Likelihood is moderate: the attacker needs the victim to first choose to install from *some* repository the attacker controls (e.g., by search ranking, social engineering, or a plausible-sounding fork), then the built-in "provenance" feature does the rest by presenting or auto-selecting the attacker's second repository. No MITM, leaked token, or privileged access is required — only publishing normal public GitHub content, which matches the "unprivileged remote attacker" and "attacker-published content" criteria in the validation rules.

### Recommendation
- Do not treat `github-repo` frontmatter as authoritative provenance; it is unauthenticated, attacker-supplied data.
- Require some independent signal before offering/using an "upstream" redirect, e.g., verifying that the claimed upstream actually contains an identical or ancestor version of the skill (content hash/commit lineage), or that the re-publisher explicitly forked from the claimed upstream via GitHub's fork API.
- Make the `--upstream` auto-redirect fail closed (reject) rather than silently trust the embedded metadata when provenance cannot be cryptographically or structurally corroborated.
- In interactive mode, clearly label the "upstream" choice as "unverified, self-declared by publisher" rather than implying it is the recommended/authoritative source.

### Proof of Concept
1. Attacker creates `attacker/evil-skills` containing a skill `foo` whose `SKILL.md` frontmatter includes `github-repo: https://github.com/attacker/evil-skills-v2` (a second attacker-controlled repo containing malicious skill content).
2. Attacker promotes `attacker/evil-skills` (e.g., via search ranking, README, social engineering) so a victim runs:
   `gh skill install attacker/evil-skills foo --upstream`
3. `checkUpstreamProvenance` reads the `github-repo` metadata (`pkg/cmd/skills/install/install.go:1299-1341`), and because `--upstream` was passed, `installRun` immediately redirects (`pkg/cmd/skills/install/install.go:1349-1352`) and recurses into installing from `attacker/evil-skills-v2` without further verification.
4. The victim ends up with skill files written to disk sourced entirely from a second attacker-chosen repository, believing they installed from a verified "upstream" source.

### Citations

**File:** pkg/cmd/skills/install/install.go (L343-373)
```go
	// to the original source repo. If detected, offer to install directly
	// from upstream instead.
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
		if detected {
			upstreamSource = "republisher"
		}
	}
```

**File:** pkg/cmd/skills/install/install.go (L1299-1341)
```go
func checkUpstreamProvenance(opts *InstallOptions, client *api.Client, hostname string, skill discovery.Skill, commitSHA string) (ghrepo.Interface, bool, error) {
	u, err := safeurl.JoinPath("repos", opts.repo.RepoOwner(), opts.repo.RepoName(), "contents", skill.Path+"/SKILL.md")
	if err != nil {
		return nil, false, err
	}
	u.SetQuery("ref", commitSHA)
	var fileResp struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := client.REST(hostname, "GET", u.String(), nil, &fileResp); err != nil {
		return nil, false, nil //nolint:nilerr // best-effort check; failing to fetch is not fatal
	}
	if fileResp.Encoding != "base64" {
		return nil, false, nil
	}
	decoded, decodeErr := io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(fileResp.Content)))
	if decodeErr != nil {
		return nil, false, nil //nolint:nilerr // best-effort; decode failure is not fatal
	}
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
	if parseErr != nil {
		//nolint:nilerr // invalid repo URL means we can't redirect; install normally
		return nil, false, nil
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
