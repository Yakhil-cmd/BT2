### Title
Unbounded blob download and disk write in `installSkill` allows disk-exhaustion DoS via oversized attacker-controlled skill files - ([File: internal/skills/installer/installer.go])

### Summary
`installSkill` fetches each skill file via `discovery.FetchBlob` and writes the fully-decoded content with `os.WriteFile` without any size cap, and `FetchBlob` itself has no limit on the JSON `content` field it reads and base64-decodes. A malicious repository publishing skills with very large blobs (e.g. multi-gigabyte files) can cause `gh skill install` to buffer and write arbitrarily large attacker-controlled data to disk, and this is not mitigated by the 5-worker concurrency cap, since concurrency limits request parallelism, not per-file or total data volume.

### Finding Description
The call chain is: `Install` (workers, `maxConcurrency = 5`) → `installSkill` → `discovery.FetchBlob` → `os.WriteFile`.

In `discovery.go`, `FetchBlob` performs `client.REST(...)` to fetch `repos/{owner}/{repo}/git/blobs/{sha}` and then does: [1](#0-0) 
There is no check on `resp.Content` length before `io.ReadAll(base64.NewDecoder(...))` decodes it fully into memory.

In `installer.go`, `installSkill` calls `FetchBlob`, takes the raw decoded bytes, and writes them verbatim: [2](#0-1) 
No `SkillFile.Size` (returned by `discovery.DiscoverSkillFiles`, which does carry a `Size` field from the tree API) is checked against any threshold before fetching or writing. The `Size` field exists in `SkillFile`/`treeEntry` but `installSkill` never consults it to reject oversized files before calling `FetchBlob`.

The worker pool in `Install` limits the number of concurrent `installSkill` calls to `min(maxConcurrency, total)` (5), which bounds the number of simultaneous downloads but does not bound the size of any single blob or the cumulative bytes written to disk. A repository listing many large blobs under a matching `skills/` convention would each be sequentially or concurrently fetched (bounded to 5 in flight) and written to disk without a total or per-file size limit.

Discovery itself does not filter out oversized files: `DiscoverSkillFiles` and `walkTree` return every blob under the skill's tree regardless of size, and `matchSkillConventions` only checks path/name patterns, not content size.

### Impact Explanation
This maps to a Denial of Service via disk exhaustion (and secondarily memory pressure from `io.ReadAll` buffering the full decoded blob before writing). Since `gh skill install` runs on behalf of a normal, unprivileged victim pulling in attacker-published repo content, an attacker who controls a "skill" repository can supply one or more oversized blobs to fill the victim's disk, potentially disrupting other operations on the host. This is a resource-exhaustion class finding rather than code execution, credential leakage, or path traversal — those other invariants (`safepaths.Join`) are correctly enforced elsewhere in `installSkill`.

### Likelihood Explanation
Feasibility is high in the sense that no privileged access is required — any GitHub user can publish a public repository with a `skills/<name>/SKILL.md` and arbitrarily large sibling files, and a victim who runs `gh skill install owner/repo` would trigger this path. However, exploitation is bounded by normal git/GitHub blob size limits (GitHub's Git Blob API and repository storage impose practical caps, e.g. the ~100MB single-file limit typically enforced by GitHub for pushes, though large files via LFS or bypassing normal push flows could differ), which somewhat limits the "arbitrarily large" characterization from the question. Still, even repeated ~100MB-scale files across multiple skills, unlimited in count, could accumulate into a meaningful DoS given no per-install or cumulative size cap exists in the code.

### Recommendation
Add a size check before fetching and writing skill files: consult `SkillFile.Size` (already returned by `DiscoverSkillFiles`) and reject/skip files exceeding a reasonable threshold (e.g., a few MB, consistent with typical skill file sizes) before calling `FetchBlob`. Additionally, harden `FetchBlob` to enforce a maximum decoded size (e.g., via `io.LimitReader` with an error on truncation) so a crafted or unexpectedly large blob response cannot be fully buffered in memory regardless of caller behavior. Consider also enforcing a cumulative byte budget per `Install` call across all skills to bound total disk usage from a single `gh skill install` invocation.

### Proof of Concept
Go test sketch using `httpmock`:
```go
func TestInstallSkill_RejectsOversizedBlob(t *testing.T) {
    reg := &httpmock.Registry{}
    // tree/contents listing returns one file, e.g. skills/evil/SKILL.md with size=200_000_000
    reg.Register(
        httpmock.REST("GET", "repos/owner/repo/git/trees/treesha"),
        httpmock.StringResponse(`{"sha":"treesha","tree":[{"path":"SKILL.md","mode":"100644","type":"blob","sha":"bigblobsha","size":200000000}]}`),
    )
    // blob endpoint returns a huge base64 content field (simulate with a generated large string)
    hugeContent := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("A"), 200_000_000))
    reg.Register(
        httpmock.REST("GET", "repos/owner/repo/git/blobs/bigblobsha"),
        httpmock.StringResponse(fmt.Sprintf(`{"sha":"bigblobsha","content":%q,"encoding":"base64"}`, hugeContent)),
    )
    client := api.NewClientFromHTTP(&http.Client{Transport: reg})

    opts := &installer.Options{Client: client, Host: "github.com", Owner: "owner", Repo: "repo", Skills: []discovery.Skill{{Name: "evil", Path: "skills/evil", TreeSHA: "treesha"}}, Dir: t.TempDir()}
    _, err := installer.Install(opts)
    // Expected (fixed) behavior: err != nil, mentioning "file too large" / size limit exceeded
    // Current (vulnerable) behavior: err == nil, and a 200MB file is written to disk with no limit
    require.Error(t, err)
}
```
Assert that, prior to a fix, `os.WriteFile` succeeds and a file of the full attacker-supplied size lands on disk with no enforced cap, confirming the missing size-bound check in both `FetchBlob` and `installSkill`.

### Citations

**File:** internal/skills/discovery/discovery.go (L936-943)
```go
	// GitHub API returns base64 with embedded newlines; use the StdEncoding
	// decoder via a reader to handle them transparently.
	decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(resp.Content)))
	if err != nil {
		return iostreams.Untrusted{}, fmt.Errorf("could not decode blob content: %w", err)
	}

	return iostreams.NewUntrustedBytes(decoded), nil
```

**File:** internal/skills/installer/installer.go (L268-305)
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
```
