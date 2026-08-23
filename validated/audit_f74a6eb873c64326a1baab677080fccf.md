### Title
Unbounded download of attacker-controlled file content via `io.ReadAll` in `fetchContent`/`fetchRawFile` - (File: pkg/cmd/repo/read-file/http.go)

### Summary
`gh repo read-file` fetches file content from the GitHub Contents API using `io.ReadAll(resp.Body)` with no size limit, in both `fetchContent` (inline base64 content) and `fetchRawFile` (raw large-file content). An attacker who controls a public repository can publish an arbitrarily large file, and a victim who runs `gh repo read-file <path> --repo attacker/repo` will have the entire response buffered into memory with no cap, size check, or streaming to disk with backpressure.

### Finding Description
`readFileRun` in [1](#0-0)  calls `fetchFile`, which calls `fetchContent`. For files exceeding the API's 1MB inline limit, `loadContent` calls `fetchRawFile` [2](#0-1) .

Both `fetchContent` and `fetchRawFile` read the entire HTTP response body via `io.ReadAll(resp.Body)` without any `io.LimitReader`, size cap, or check against a `Content-Length`/declared size before reading: [3](#0-2) [4](#0-3) 

The file's declared `Size` field from the Contents API response (`content.Size`) is stored in the returned `repoFile` struct [5](#0-4)  but it is never used to bound the actual read — it's purely informational (used later e.g. for display in the binary-file error message). Since the attacker fully controls the repository content (as owner of a public repo, fork, or via a crafted file at any ref/branch), they control both the declared size and the actual byte count of the response body, and can also make the response an effectively endless stream (e.g. via a slow/chunked transfer) since there is no read deadline or cap tied to this call path beyond whatever the shared `httpClient`/transport enforces generically (none apparent here).

The result is that a single `gh repo read-file` invocation against an attacker-controlled path can force the client to buffer unbounded bytes into memory (`[]byte`), which is then also fully loaded again for base64 decoding in `fetchFile` [6](#0-5) , further multiplying memory pressure.

### Impact Explanation
This matches a High-severity unbounded resource consumption issue: a single attacker-published file (in a repo, at any ref, since `--ref` is attacker-influenceable when the attacker owns the target repo) can exhaust victim memory or fill disk space (when combined with `--output`) by simply publishing an oversized or slow-streaming file and inducing/waiting for the victim to run `gh repo read-file` against it. No credentials, code execution, or elevated privileges are needed — only that the victim points `gh` at attacker-controlled content, which is a normal use case for this preview command (reading files from arbitrary/untrusted repos without cloning).

### Likelihood Explanation
Feasible and repeatable: the attacker only needs a public GitHub repository (or fork) containing a very large file, and the victim needs to run `gh repo read-file <path> --repo attacker/repo` (a documented, expected usage pattern of this exact command). There is no rate limiting or size gate on the client side to prevent this regardless of how many times it's triggered.

### Recommendation
Bound the response body reads in both `fetchContent` and `fetchRawFile` using `io.LimitReader(resp.Body, maxSize+1)` (or similar), checking `resp.ContentLength` when available and rejecting responses exceeding a sane maximum (e.g., a few hundred MB), returning a clear "file too large" error to the user instead of silently buffering unbounded bytes. Consider streaming large writes directly to the `--output` destination rather than loading full contents into memory first.

### Proof of Concept
```go
func TestFetchRawFile_UnboundedRead(t *testing.T) {
    // httpmock server that streams an effectively endless/huge body
    // (e.g., io.Pipe or a handler writing >1GB of bytes with chunked transfer,
    // or writing indefinitely with no Content-Length)
    reg := &httpmock.Registry{}
    reg.Register(
        httpmock.REST("GET", "repos/attacker/repo/contents/huge.bin"),
        func(req *http.Request) (*http.Response, error) {
            pr, pw := io.Pipe()
            go func() {
                buf := make([]byte, 1<<20) // 1MB chunk
                for {
                    if _, err := pw.Write(buf); err != nil {
                        return
                    }
                }
            }()
            return &http.Response{
                StatusCode: 200,
                Body:       pr,
                Header:     http.Header{"Content-Type": {"application/vnd.github.raw"}},
            }, nil
        },
    )
    client := &http.Client{Transport: reg}
    repo, _ := ghrepo.FromFullName("attacker/repo")

    done := make(chan error, 1)
    go func() {
        _, err := fetchRawFile(client, repo, "huge.bin", "")
        done <- err
    }()

    select {
    case <-done:
        t.Fatal("expected fetchRawFile to be bounded and return an error before completing an endless read")
    case <-time.After(5 * time.Second):
        // Confirms unbounded read: fetchRawFile never returns/errors on an endless stream,
        // consuming unbounded memory instead of failing fast.
    }
}
```
Expected (fixed) behavior: `fetchRawFile`/`fetchContent` should return a bounded "file too large" error quickly instead of hanging or consuming unbounded memory.

### Citations

**File:** pkg/cmd/repo/read-file/read_file.go (L128-143)
```go
func readFileRun(opts *ReadFileOptions) error {
	httpClient, err := opts.HttpClient()
	if err != nil {
		return err
	}

	repo, err := opts.BaseRepo()
	if err != nil {
		return fmt.Errorf("%w. Run this command from within a git repository, or use the `--repo` flag to specify one", err)
	}

	file, err := fetchFile(httpClient, repo, opts.Path, opts.Ref)
	if err != nil {
		return err
	}

```

**File:** pkg/cmd/repo/read-file/read_file.go (L213-227)
```go
// loadContent fetches the raw file bytes when the Contents API did not return them inline.
// The API only omits inline content for large files, which it marks with a "none" encoding;
// everything else (including empty files) comes back base64-encoded, so there is nothing to fetch.
func loadContent(httpClient *http.Client, repo ghrepo.Interface, file *repoFile, ref string) error {
	if file.Encoding != "none" {
		return nil
	}

	raw, err := fetchRawFile(httpClient, repo, file.Path, ref)
	if err != nil {
		return err
	}
	file.Content = raw
	return nil
}
```

**File:** pkg/cmd/repo/read-file/http.go (L106-119)
```go
	if resp.StatusCode > 299 {
		return nil, api.HandleHTTPError(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var content contentsResponse
	if err := json.Unmarshal(body, &content); err != nil {
		return nil, err
	}
	return &content, nil
```

**File:** pkg/cmd/repo/read-file/http.go (L150-161)
```go
	file := &repoFile{
		Name:        content.Name,
		Path:        content.Path,
		SHA:         content.SHA,
		Size:        content.Size,
		URL:         content.URL,
		HTMLURL:     content.HTMLURL,
		GitURL:      content.GitURL,
		DownloadURL: content.DownloadURL,
		Type:        content.Type,
		Encoding:    content.Encoding,
	}
```

**File:** pkg/cmd/repo/read-file/http.go (L163-169)
```go
	if content.Encoding == "base64" && content.Content != "" {
		decoded, err := base64.StdEncoding.DecodeString(content.Content)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 file content: %w", err)
		}
		file.Content = decoded
	}
```

**File:** pkg/cmd/repo/read-file/http.go (L188-198)
```go
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return nil, api.HandleHTTPError(resp)
	}

	return io.ReadAll(resp.Body)
```
