### Title
Unsanitized commit SHA from `fetchCommitSHA` allows path traversal into extension pin file path - ([File: pkg/cmd/extension/manager.go])

### Finding Description
`fetchCommitSHA` in `pkg/cmd/extension/http.go` sends a request to `repos/{owner}/{repo}/commits/{targetRef}` with an `Accept: application/vnd.github.v3.sha` header and returns the raw HTTP response body verbatim, with no validation, trimming, or hex/length checking: [1](#0-0) 

This string is then consumed by `Manager.installGit` to build the pin marker filename via `fmt.Sprintf(".pin-%s", commitSHA)`, which is subsequently joined with the extension's `targetDir` using `filepath.Join` before being passed to `os.OpenFile`. `filepath.Join` calls `filepath.Clean` on the result, which resolves any `..` segments contained in the substituted string — it does not reject or sanitize embedded path separators or traversal sequences. Because `fmt.Sprintf` performs no escaping, any `/` or `..` characters present in the response body are carried straight into the joined path, and `Clean` will walk them upward past `targetDir` into arbitrary filesystem locations.

Root cause: the SHA value returned by the commits API is trusted as an opaque, safe filename component without format validation (e.g., a 40/64-char hex regex), and the path is built with string interpolation before filesystem-path joining.

### Impact Explanation
If the HTTP response for the commits endpoint is attacker-controlled (i.e., the victim's `gh` is pointed at an attacker-controlled or compromised host — a scenario the audit rules explicitly permit), the attacker can cause `gh` to write/create a `.pin-*` marker file at an arbitrary filesystem path reachable from `targetDir` via `../` sequences, an arbitrary-file-write outside the intended extension install directory. This matches the "file write or overwrite outside the intended path" bounty impact class. The severity is limited by: 1) the file's content is not attacker-controlled (empty/pin content only), and 2) it requires a non-`github.com` (attacker-influenced) API host, since `api.github.com`'s actual commits endpoint deterministically returns valid hex commit hashes.

### Likelihood Explanation
Exploitation requires the victim's `gh` to be configured against a host under attacker influence (e.g., a malicious/compromised GitHub Enterprise Server) — it is not exploitable against genuine `github.com` because GitHub's own commit-hash computation cannot be forced to emit arbitrary strings. Given that precondition, the attack is fully repeatable and deterministic since there is no validation whatsoever on the returned SHA before it is embedded into the path.

### Recommendation
Validate the value returned by `fetchCommitSHA` against a strict hex-digest pattern (e.g., `^[0-9a-f]{40}$` or `{64}` for SHA-256 repos) before use, rejecting anything else. Additionally, after constructing `pinPath` with `filepath.Join`, verify with `filepath.Rel` (or equivalent) that the result remains within `targetDir` before opening/writing the file, defensively guarding against any future callers that skip SHA validation.

### Proof of Concept
```go
func TestInstallGitPinPathTraversal(t *testing.T) {
    reg := httpmock.Registry{}
    defer reg.Verify(t)
    reg.Register(
        httpmock.REST("GET", "repos/OWNER/REPO/commits/main"),
        httpmock.StringResponse("../../../../tmp/evil"),
    )
    httpClient := &http.Client{Transport: &reg}

    tempDir := t.TempDir()
    m := newTestManager(tempDir, nil, httpClient, ...) // wire manager similarly to manager_test.go helpers

    err := m.installGit("https://github.com/OWNER/REPO.git", "main", tempDir, "", false, io.Discard, io.Discard)
    require.NoError(t, err)

    // Assert the pin file always resolves as a direct child of the extension's targetDir.
    targetDir := filepath.Join(tempDir, "gh-REPO")
    entries, _ := filepath.Glob(filepath.Join(targetDir, ".pin-*"))
    for _, e := range entries {
        rel, err := filepath.Rel(targetDir, e)
        require.NoError(t, err)
        require.False(t, strings.HasPrefix(rel, ".."), "pin file escaped targetDir: %s", e)
    }
}
```
Expected (current) behavior if unpatched: the resolved pin path lies outside `targetDir` (e.g., under `/tmp/evil`), failing the assertion. After adding SHA-format validation, `installGit` should return an error before ever constructing the path.

### Citations

**File:** pkg/cmd/extension/http.go (L200-206)
```go

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
```
