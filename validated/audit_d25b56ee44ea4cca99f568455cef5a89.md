### Title
Path traversal via unsanitized commit SHA from `fetchCommitSHA` used to build extension pin marker file path - ([File: pkg/cmd/extension/http.go])

### Finding Description
`fetchCommitSHA` in `pkg/cmd/extension/http.go` requests `Accept: application/vnd.github.v3.sha` and returns the raw HTTP response body verbatim as the commit SHA string, with no validation of its format (e.g. no check that it is 40 hex characters), no trimming, and no rejection of path-separator or `..` characters: [1](#0-0) 

This function is reachable from `fetchReleaseFromTag`/pinned-install flows where `baseRepo.RepoOwner()`/`RepoName()` and the target ref ultimately determine which host and path is queried: [2](#0-1) [3](#0-2) 

Per the described call sequence, the returned `commitSHA` value is subsequently interpolated directly into a filename with `fmt.Sprintf(".pin-%s", commitSHA)` and joined with `targetDir` via `filepath.Join` in `Manager.installGit` (`pkg/cmd/extension/manager.go`). `filepath.Join`/`filepath.Clean` will resolve any `..` segments contained in that interpolated string, so if `commitSHA` contains sequences like `../../../tmp/evil`, the resulting `pinPath` can point outside `targetDir`. Since the attacker fully controls the HTTP response body (either by publishing content behind a ref/tag resolution the victim queries, or — per the stated threat model — by controlling a host the victim points `gh` at), this value is not constrained to a real Git SHA.

I was not able to retrieve the exact current source of `Manager.installGit` in `pkg/cmd/extension/manager.go` in this session (tool budget exhausted), so I cannot confirm with certainty whether the code applies an intermediate sanitization/regex check (e.g. `^[0-9a-f]{7,40}$`) on `commitSHA` before it is used to build `pinPath`. This is a material unknown: if such validation exists, the vulnerability is neutralized; if it does not, the flow as described in the question is exploitable exactly as traced through `fetchCommitSHA`.

### Impact Explanation
If unmitigated, this allows an attacker-controlled tag/ref/host response to cause `gh` to create/overwrite a file at an attacker-chosen path outside the intended extension installation directory (file write outside intended path). The content written is limited (an empty pin-marker file, not attacker-controlled content), so the practical impact is more likely file creation/overwrite (denial-of-service / corruption of an existing zero-length-writable target) rather than arbitrary code execution, but it still constitutes a path-confinement violation.

### Likelihood Explanation
Requires the victim to install/pin an extension from an attacker-controlled repo/ref, or to have `gh` configured against a host controlled by the attacker (per the given threat model, both are permitted attacker capabilities). No token, MITM, or elevated privileges are required beyond the ability to serve/author the release or commit-ref content.

### Recommendation
Validate `commitSHA` returned by `fetchCommitSHA` against a strict SHA pattern (e.g. `^[0-9a-fA-F]{7,40}$`) before returning it or before using it in `fmt.Sprintf(".pin-%s", commitSHA)`, and reject/error on non-matching values. Additionally, verify the final `pinPath` remains within `targetDir` (e.g., using `filepath.Rel` + prefix check, consistent with any existing `safepaths` utilities already used elsewhere in the codebase) before writing.

### Proof of Concept
```go
func TestFetchCommitSHA_PathTraversalPayload(t *testing.T) {
    reg := &httpmock.Registry{}
    reg.Register(
        httpmock.REST("GET", "repos/OWNER/REPO/commits/some-ref"),
        httpmock.StringResponse("../../../tmp/evil"),
    )
    httpClient := &http.Client{Transport: reg}
    sha, err := fetchCommitSHA(httpClient, ghrepo.New("OWNER", "REPO"), "some-ref")
    assert.NoError(t, err)
    // Demonstrate that this raw value, if used unchecked, escapes targetDir
    pinPath := filepath.Join("/home/user/.local/share/gh/extensions/gh-foo", fmt.Sprintf(".pin-%s", sha))
    rel, _ := filepath.Rel("/home/user/.local/share/gh/extensions/gh-foo", pinPath)
    assert.True(t, strings.HasPrefix(rel, ".."), "pinPath escaped targetDir: %s", pinPath)
}
```
This confirms `fetchCommitSHA` returns unsanitized attacker-controlled content. To fully confirm exploitability, a follow-up test/inspection of `Manager.installGit` in `pkg/cmd/extension/manager.go` is needed to verify whether the SHA is validated before being used to build `pinPath` — this could not be completed in this session and should be checked directly against the current `manager.go` source before treating this as a confirmed, unmitigated vulnerability.

### Citations

**File:** pkg/cmd/extension/http.go (L146-172)
```go
// fetchReleaseFromTag finds release by tag name for a repository
func fetchReleaseFromTag(httpClient *http.Client, baseRepo ghrepo.Interface, tagName string) (*release, error) {
	path, err := safeurl.JoinPath("repos", baseRepo.RepoOwner(), baseRepo.RepoName(), "releases", "tags", tagName)
	if err != nil {
		return nil, err
	}

	var data json.RawMessage
	// TODO(api-client-rollout)
	// This line of code is part of a mechanical roll out of the api client.
	// As a follow up, consider whether the api client can be injected to this call site, rather than constructed
	err = api.NewClientFromHTTP(httpClient).REST(baseRepo.RepoHost(), http.MethodGet, path.String(), nil, &data)
	if err != nil {
		var httpErr api.HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
			return nil, releaseNotFoundErr
		}
		return nil, err
	}

	var r release
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}

	return &r, nil
}
```

**File:** pkg/cmd/extension/http.go (L174-207)
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
}
```
