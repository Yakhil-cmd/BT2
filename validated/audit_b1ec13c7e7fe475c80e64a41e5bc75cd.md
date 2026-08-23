Confirmed: `GetRawGistFile` reads the entire raw gist file response into memory with `io.ReadAll(resp.Body)` and no size cap, and this is reachable via `gh gist view`/`gh gist edit` on a gist ID or URL supplied by the user (which can point to any gist, including an attacker-owned/published one) via `pkg/cmd/gist/view/view.go` and `pkg/cmd/gist/edit/edit.go`. There is no `io.LimitReader` anywhere in the codebase, confirming this is unbounded.

### Title
Unbounded response body read in GetRawGistFile leading to memory exhaustion - (File: pkg/cmd/gist/shared/shared.go)

### Summary
`GetRawGistFile` fetches a gist's raw file content and reads the entire HTTP response body into memory via `io.ReadAll(resp.Body)` with no size limit. Because the raw URL points to gist content that can be entirely attacker-controlled (an attacker's own public gist), a victim running `gh gist view <id>` or `gh gist edit <id>` against an attacker-published gist can be forced to buffer an arbitrarily large response into memory.

### Finding Description
`GetRawGistFile` in [1](#0-0)  issues a GET request to `rawURL` and calls `body, err := io.ReadAll(resp.Body)` without wrapping the reader in any `io.LimitReader` or otherwise checking `Content-Length`/imposing a cap. The `rawURL` is derived from gist file metadata returned by the GitHub API for a gist selected by the user (by ID/URL), and an attacker fully controls the content and size of a gist they create/own, including its raw file bytes served from `gist.githubusercontent.com` (or, in an enterprise/host-parameterized context, from whatever host is configured). This function is invoked from `pkg/cmd/gist/view/view.go` and `pkg/cmd/gist/edit/edit.go` whenever a victim views or edits an attacker-shared gist. A grep of the codebase confirms there is no `io.LimitReader` usage anywhere, so no bounding mechanism exists at this call site.

### Impact Explanation
An attacker can publish a public gist whose raw file content is many gigabytes (or an endless/slow-drip stream), and get a victim to run `gh gist view <attacker-gist-id>` or `gh gist edit <attacker-gist-id>`. The victim process will attempt to buffer the entire response in memory, leading to excessive memory consumption and potential OOM/crash/denial of service on the victim's machine — matching the "Unbounded resource consumption" / DoS impact class for a client tool.

### Likelihood Explanation
Feasible and repeatable: an unprivileged attacker only needs to create a public gist (or any resource whose raw URL is fetched by this code path) with a very large or infinite body and share the ID/URL with the victim. No special privileges, tokens, or MITM are required — a normal `gh gist view`/`gh gist edit` invocation against attacker content triggers it every time.

### Recommendation
Wrap `resp.Body` in `io.LimitReader(resp.Body, maxGistFileSize)` before calling `io.ReadAll`, choosing a sane cap (e.g. matching GitHub's gist raw file size limits), and return an explicit "file too large" error when the limit is exceeded, consistent with how other unbounded-download findings in this codebase should be remediated.

### Proof of Concept
```go
func TestGetRawGistFile_UnboundedBody(t *testing.T) {
	reg := &httpmock.Registry{}
	// Simulate an endless/huge body from the raw gist URL.
	reg.Register(
		httpmock.REST("GET", "huge-gist-file"),
		httpmock.RawResponder(200, io.LimitReader(neverEndingReader{}, math.MaxInt64)), // effectively unbounded
	)
	httpClient := &http.Client{Transport: reg}

	u, _ := safeurl.Parse("https://gist.githubusercontent.com/huge-gist-file")
	_, err := shared.GetRawGistFile(httpClient, u)

	// Expected (fixed) behavior: bounded error such as "gist file exceeds maximum allowed size"
	// Actual (current) behavior: unbounded memory growth / process OOM before returning.
	require.Error(t, err)
}
```
This test demonstrates that, absent a limit reader, `GetRawGistFile` has no mechanism to reject or cap an oversized/never-ending response body.

### Citations

**File:** pkg/cmd/gist/shared/shared.go (L258-281)
```go
func GetRawGistFile(httpClient *http.Client, rawURL safeurl.SafeURL) (iostreams.Untrusted, error) {
	req, err := http.NewRequest("GET", rawURL.String(), nil)
	if err != nil {
		return iostreams.Untrusted{}, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return iostreams.Untrusted{}, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return iostreams.Untrusted{}, api.HandleHTTPError(resp)
	}

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		return iostreams.Untrusted{}, err
	}

	return iostreams.NewUntrustedBytes(body), nil
```
