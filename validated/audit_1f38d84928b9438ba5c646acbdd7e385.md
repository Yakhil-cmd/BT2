### Title
Unvalidated `fetchCommitSHA` response used to build `pinPath` allows path traversal / arbitrary file creation outside the extension's `targetDir` - ([File: pkg/cmd/extension/manager.go])

### Summary
`fetchCommitSHA` in [1](#0-0)  reads the raw HTTP response body and returns it as a string with no format validation (no regex/length check confirming it is a 40-hex-char SHA). `Manager.installGit` in `pkg/cmd/extension/manager.go` consumes this string directly to build `pinPath := filepath.Join(targetDir, fmt.Sprintf(".pin-%s", commitSHA))`, which is then passed to `os.OpenFile`. Because `filepath.Join` cleans `..` segments, an attacker-controlled commit-ref response containing `../` sequences can cause the pin marker file to be created outside `targetDir`.

### Finding Description
`fetchCommitSHA` sends `GET repos/{owner}/{repo}/commits/{targetRef}` with `Accept: application/vnd.github.v3.sha` and returns `string(body)` verbatim: [2](#0-1) . There is no check that the returned body actually looks like a git SHA (e.g., `^[0-9a-f]{40}$`). If the victim's `gh` client is pointed at a host controlled by (or compromised in front of) the attacker — a scenario explicitly in-scope per the "controls responses from a host the victim points gh at" precondition — the attacker can return an arbitrary string such as `../../../../tmp/evil` instead of a SHA.

`Manager.installGit` uses this returned `commitSHA` value to build a "pin" marker filename via `fmt.Sprintf(".pin-%s", commitSHA)` and joins it to `targetDir` with `filepath.Join`, then opens/creates it with `os.OpenFile`. `filepath.Join` calls `filepath.Clean`, which resolves `..` components, so a crafted `commitSHA` such as `../../../../tmp/evil` collapses the resulting path outside the intended extensions directory. No allowlist, safepaths-style confinement, or SHA-format validation exists between `fetchCommitSHA`'s return value and the `os.OpenFile` sink, so the write primitive is reachable end-to-end: attacker-controlled ref-lookup response → `commitSHA` → `pinPath` → `os.OpenFile`.

### Impact Explanation
This yields an arbitrary (empty) file-creation primitive outside the extensions directory, matching the "file write outside intended path" bounty impact class. Impact is limited to creating a zero-length file at an attacker-chosen path relative to `targetDir` (bounded by the depth of `..` segments and file-system permissions of the `gh` process); it does not directly overwrite existing file contents unless the flags/mode used with `os.OpenFile` include truncation of an existing writable file, in which case impact could extend to truncating an existing file the user has write access to.

### Likelihood Explanation
Exploitation requires the victim to install a *pinned* git-based extension from a repository/host where the attacker controls (or can spoof) the `commits/<ref>` API response — e.g., a malicious or compromised GitHub Enterprise Server host the victim has configured, or any host reachable by `gh` whose commit-lookup endpoint the attacker controls. This is a realistic but narrower precondition than a plain public GitHub.com extension install, since GitHub.com's real API would not return attacker-chosen arbitrary text for that endpoint. Under the stated threat model (attacker controls responses from a host the victim points `gh` at), the attack is straightforward and repeatable.

### Recommendation
Validate the value returned by `fetchCommitSHA` before using it anywhere in path construction: enforce a strict regex (e.g., `^[0-9a-f]{7,40}$`) and reject/error out otherwise. Additionally, harden `pinPath` construction by verifying (e.g., via `filepath.Rel` + checking for no `..` prefix, or comparing `filepath.Clean(pinPath)` against `targetDir` with a prefix check) that the resulting path stays within `targetDir` before calling `os.OpenFile`.

### Proof of Concept
```go
func TestFetchCommitSHA_PathTraversalRejected(t *testing.T) {
    reg := httpmock.Registry{}
    reg.Register(
        httpmock.REST("GET", "repos/owner/repo/commits/HEAD"),
        httpmock.StringResponse("../../../../tmp/evil"),
    )
    client := &http.Client{Transport: &reg}
    repo := ghrepo.New("owner", "repo")

    sha, err := fetchCommitSHA(client, repo, "HEAD")
    // Expected (fix): either an error is returned because the response
    // does not match a SHA pattern, or callers reject it before use.
    if err == nil {
        t.Fatalf("expected validation error for non-SHA response, got sha=%q", sha)
    }
}

func TestInstallGit_PinPathConfinement(t *testing.T) {
    targetDir := t.TempDir()
    commitSHA := "../../../../tmp/evil" // simulate malicious fetchCommitSHA result
    pinPath := filepath.Join(targetDir, fmt.Sprintf(".pin-%s", commitSHA))
    if !strings.HasPrefix(filepath.Clean(pinPath), filepath.Clean(targetDir)+string(os.PathSeparator)) {
        t.Fatalf("pinPath escapes targetDir: %s", pinPath)
    }
}
```
Expected result after fix: `fetchCommitSHA` (or `installGit`) rejects the malformed SHA before it reaches `filepath.Join`/`os.OpenFile`, and no file is created outside `targetDir`.

### Citations

**File:** pkg/cmd/extension/http.go (L174-206)
```go
// fetchCommitSHA finds full commit SHA from a target ref in a repo
func fetchCommitSHA(httpClient *http.Client, baseRepo ghrepo.Interface, targetRef string) (string, error) {
	url, err := safeurl.JoinPathWithHostPrefix(ghinstance.RESTPrefix(baseRepo.RepoHost()), "repos", baseRepo.RepoOwner(), baseRepo.RepoName(), "commits", targetRef)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/vnd.github.v3.sha")
	// TODO(api-client-rollout)
	// This has been deferred from moving to api.Client due to its custom Accept header and bare SHA response body.
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	if resp.StatusCode == 422 {
		return "", commitNotFoundErr
	}
	if resp.StatusCode > 299 {
		return "", api.HandleHTTPError(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
```
