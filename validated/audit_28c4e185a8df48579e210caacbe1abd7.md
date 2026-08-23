### Title
Unbounded `io.Copy` of remote release asset/archive body allows disk and memory exhaustion - (File: pkg/cmd/release/download/download.go)

### Summary
`downloadAsset` fetches the response body of a release asset or source archive with no size limit and hands it to `destinationWriter.Copy`, which performs a raw `io.Copy(f, r)` (or `io.Copy(w.stdout, r)` / `io.ReadAll(r)` for the stdout/text path) with no cap on bytes read. A malicious or compromised host serving release/gist/artifact/archive content with an endless body (no `Content-Length`, chunked transfer) can force `gh release download` to write unbounded data to disk or buffer unbounded data in memory until resources are exhausted.

### Finding Description
In `downloadRun` (`pkg/cmd/release/download/download.go:142`), asset URLs come directly from the release metadata (`a.APIURL`, `release.TarballURL`, `release.ZipballURL`), which is attacker-controlled content published as part of a release on a repository the victim points `gh` at. These are wrapped in `safeurl.NewImmutableSafeURL` and passed to `downloadAsset` [1](#0-0) , which only validates the URL's host/scheme, not the size of the response.

`downloadAsset` issues an HTTP GET and passes `resp.Body` straight to `dest.Copy` without ever consulting `resp.ContentLength` or wrapping the reader in a limiter [2](#0-1) .

`destinationWriter.Copy` then performs a plain `io.Copy(f, r)` when writing to a file [3](#0-2) , and for the stdout path with `--allow-escape-sequences` does `io.Copy(w.stdout, r)` directly [4](#0-3) . Even the "guarded" stdout path in `CopyGuardedContent` reads the entire body into memory via `io.ReadAll(r)` for textual content, or streams unbounded via `io.Copy` for binary content [5](#0-4) . None of these paths impose an explicit limit reader, so a server can serve an effectively infinite response and both the disk-write and memory-buffering code paths will keep consuming resources indefinitely.

### Impact Explanation
An attacker who publishes a release (or controls a host referenced by a release asset/archive URL) can cause `gh release download` to consume unbounded disk space or unbounded memory on the victim's machine, leading to denial of service (disk exhaustion, OOM) with a single attacker-published object and no other privilege required. This matches "Unbounded resource consumption" impact.

### Likelihood Explanation
High feasibility: any GitHub user can publish a release with assets pointing to endpoints they control, or exploit an already-permissive host response (no `Content-Length`, chunked, streaming from `/dev/zero`-like source). No authentication bypass, MITM, or victim misconfiguration beyond running an ordinary `gh release download` (or `--archive`) is required. Repeatable on demand.

### Recommendation
Wrap `resp.Body` in `io.LimitReader` (or a size-tracking reader that errors past a maximum, e.g. a few hundred MB configurable ceiling) before it reaches `destinationWriter.Copy`, and apply the same bound in `iostreams.CopyGuardedContent`'s `io.ReadAll` and `io.Copy` calls. Optionally pre-check `resp.ContentLength` when available and reject/warn on absurd sizes, but the primary fix must be an explicit cap enforced during the copy loop rather than relying on advertised length.

### Proof of Concept
```go
func TestDownloadAsset_UnboundedBody(t *testing.T) {
    // infiniteReader never returns io.EOF, simulating a malicious/streaming host.
    type infiniteReader struct{}
    // Read always fills buf with zero bytes and returns len(buf), nil.

    reg := &httpmock.Registry{}
    // stub asset endpoint to return an http.Response whose Body is an infinite io.Reader
    reg.Register(
        httpmock.REST("GET", "path/to/asset"),
        func(req *http.Request) (*http.Response, error) {
            return &http.Response{
                StatusCode: 200,
                Body:       io.NopCloser(infiniteReader{}),
                Header:     http.Header{"Content-Type": {"application/octet-stream"}},
                // No Content-Length set
            }, nil
        },
    )

    httpClient := &http.Client{Transport: reg}
    dest := destinationWriter{dir: t.TempDir()}
    url := safeurl.NewImmutableSafeURL("https://example.com/path/to/asset")

    done := make(chan error, 1)
    go func() { done <- downloadAsset(&dest, httpClient, url, "asset.bin", false) }()

    select {
    case err := <-done:
        t.Fatalf("expected download to be capped and error out, got: %v", err)
    case <-time.After(5 * time.Second):
        t.Fatal("download did not terminate: io.Copy has no size limit, unbounded write in progress")
    }
}
```
Expected (fixed) behavior: the copy should stop and return an error like "asset exceeds maximum allowed size" once a bounded limit is hit, rather than running indefinitely / writing unbounded bytes to disk.

### Citations

**File:** pkg/cmd/release/download/download.go (L237-245)
```go
	targets := make([]downloadTarget, len(toDownload))
	for i, a := range toDownload {
		targets[i] = downloadTarget{
			url:  safeurl.NewImmutableSafeURL(a.APIURL),
			name: a.Name,
		}
	}

	return downloadAssets(&dest, httpClient, targets, opts.Concurrency, isArchive, opts.IO)
```

**File:** pkg/cmd/release/download/download.go (L326-350)
```go
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return api.HandleHTTPError(resp)
	}

	if len(fileName) == 0 {
		contentDisposition := resp.Header.Get("Content-Disposition")

		_, params, err := mime.ParseMediaType(contentDisposition)
		if err != nil {
			return fmt.Errorf("unable to parse file name of archive: %w", err)
		}
		if serverFileName, ok := params["filename"]; ok {
			fileName = filepath.Base(serverFileName)
		} else {
			return errors.New("unable to determine file name of archive")
		}
	}

	return dest.Copy(fileName, resp.Body)
```

**File:** pkg/cmd/release/download/download.go (L416-422)
```go
func (w destinationWriter) Copy(name string, r io.Reader) (copyErr error) {
	fp := w.makePath(name)
	if fp == "-" {
		if w.allowEscapes {
			_, copyErr = io.Copy(w.stdout, r)
			return
		}
```

**File:** pkg/cmd/release/download/download.go (L441-453)
```go
	var f *os.File
	if f, copyErr = os.OpenFile(fp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644); copyErr != nil {
		return
	}

	defer func() {
		if err := f.Close(); copyErr == nil && err != nil {
			copyErr = err
		}
	}()

	_, copyErr = io.Copy(f, r)
	return
```

**File:** pkg/iostreams/content.go (L63-92)
```go
func CopyGuardedContent(w io.Writer, r io.Reader, isTTY bool) error {
	head := make([]byte, contentSniffLen)
	n, err := io.ReadFull(r, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	head = head[:n]

	if mime, ok := BinaryContentType(head); ok {
		if isTTY {
			return BinaryTerminalError{MIME: mime}
		}
		if _, err := w.Write(head); err != nil {
			return err
		}
		_, err := io.Copy(w, r)
		return err
	}

	rest, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	content := append(head, rest...)
	if ContainsEscapeSequence(content) {
		return ErrEscapeSequence
	}
	_, err = w.Write(content)
	return err
}
```
