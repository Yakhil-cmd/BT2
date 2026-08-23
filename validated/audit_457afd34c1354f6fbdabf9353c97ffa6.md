### Title
Unbounded `io.ReadAll` in `CopyGuardedContent` allows memory-exhaustion DoS via `gh release download -O -` on a malicious text-classified asset - ([File: pkg/iostreams/content.go])

### Summary
`CopyGuardedContent` reads the entire remainder of the response body into memory with `io.ReadAll` whenever the leading 512 bytes are classified as textual, with no size limit anywhere in the call chain from `downloadAsset`/`destinationWriter.Copy`. A malicious release (or a malicious archive/codeload endpoint reached via `--archive`) can stream an effectively unbounded body of clean text bytes to a victim running `gh release download ... -O -`, forcing the client to buffer the entire stream in memory and exhausting it, regardless of any `Content-Length` header sent (or omitted) by the server.

### Finding Description
`downloadAsset` in `pkg/cmd/release/download/download.go` fetches `resp.Body` from a URL controlled by the release metadata (`a.APIURL`, wrapped only by `safeurl.NewImmutableSafeURL` for SSRF/host protections, not for size) and passes it directly to `dest.Copy(fileName, resp.Body)` [1](#0-0) . When the destination is `-` (stdout) and `--allow-escape-sequences` is not set, `destinationWriter.Copy` forwards the raw, unbounded `io.Reader` into `iostreams.CopyGuardedContent(w.stdout, r, w.isTTY)` [2](#0-1) .

Inside `CopyGuardedContent`, only the first `contentSniffLen` (512) bytes are inspected via `BinaryContentType`; if that classifies as text (e.g. `strings.HasPrefix(ct, "text/")`), the function calls `rest, err := io.ReadAll(r)` with no cap, buffering the entire remaining stream before it ever checks for escape sequences or writes anything out [3](#0-2) . There is no `Content-Length` validation, no `io.LimitReader`, and no streaming write-as-you-go path for the textual branch — the whole body must be materialized in a single `[]byte` (`content := append(head, rest...)`) before `w.Write(content)` runs. Repo-wide search confirms no `LimitReader`/`MaxBytesReader` is used anywhere in this download path [4](#0-3) .

Because HTTP responses are read as `io.Reader` streams by the standard library, a server (the "release asset" endpoint reachable via the attacker-controlled `APIURL`, or an archive/codeload host) can send `Transfer-Encoding: chunked` with an effectively infinite stream of ASCII/UTF-8 bytes; the client has no way to know the true size in advance and no code path enforces one. `resp.ContentLength` (from any `Content-Length` header) is never consulted to bound the read, so even a mismatched or absent `Content-Length` has no bearing — the vulnerability is that no length is ever enforced at all.

### Impact Explanation
This is a client-side denial-of-service: an attacker who controls (or can get a victim to fetch) a release asset, or a source-archive endpoint via `--archive=zip|tar.gz`, can cause the `gh` process to attempt to buffer an unbounded amount of data in memory, exhausting the victim's memory/causing the process (and potentially the host, under memory pressure) to crash or become unresponsive. This matches GitHub's "resource exhaustion / denial of service" impact class for the CLI client. It requires the output target to be a TTY and destination `-O -` (stdout) with default escape-sequence protection enabled, and the content to sniff as non-binary in the first 512 bytes — both conditions are trivially satisfiable by the attacker who fully controls the asset bytes.

### Likelihood Explanation
- Preconditions: victim must run `gh release download <tag> -O -` (or the equivalent for `--archive` with output redirected in a way that keeps `isTTY` true, or more generally hits the textual branch) against a repository/release controlled by the attacker (public repo, fork, or any release the victim is directed to download from).
- The attacker fully controls the asset's bytes and can trivially keep the first 512 bytes ASCII/text (e.g., all spaces or repeated benign text) to force the textual branch, then continue streaming without bound using chunked transfer encoding.
- No authentication, redirect, or host bypass is needed beyond the victim voluntarily downloading the attacker's release asset, which is the exact intended use case of `gh release download`.
- This is straightforward to reproduce and highly repeatable.

### Recommendation
Bound the amount of data `CopyGuardedContent` (and/or `downloadAsset`) will buffer/stream, e.g.:
- Enforce a hard cap using `io.LimitReader` (returning an explicit error when the cap is exceeded) before doing content sniffing and buffering, independent of any `Content-Length` header.
- Prefer a streaming design for the textual branch too: scan for escape sequences incrementally (e.g., in chunks) rather than fully buffering the response with `io.ReadAll`, or fall back to unguarded direct streaming once a size threshold is exceeded (documenting the reduced guarantee).
- Optionally check `resp.ContentLength` early and reject/prompt when it is unusually large or unknown (`-1`) combined with the textual/TTY path, while still enforcing the read-time cap as the ultimate defense (headers alone cannot be trusted).

### Proof of Concept
```go
func TestCopyGuardedContent_UnboundedTextMemory(t *testing.T) {
    // Simulate an attacker-controlled, unbounded text stream (e.g. from an
    // httpmock'd release asset response with chunked transfer encoding).
    pr, pw := io.Pipe()
    go func() {
        buf := bytes.Repeat([]byte("A"), 1<<20) // 1MiB of clean ASCII per write
        for {
            if _, err := pw.Write(buf); err != nil {
                return
            }
        }
    }()

    var sink bytes.Buffer
    done := make(chan error, 1)
    go func() {
        done <- iostreams.CopyGuardedContent(&sink, pr, true /* isTTY */)
    }()

    select {
    case <-done:
        t.Fatal("CopyGuardedContent returned unexpectedly for an infinite stream")
    case <-time.After(5 * time.Second):
        // Still blocked inside io.ReadAll, having buffered gigabytes with no cap.
        // In production this manifests as unbounded RSS growth / OOM kill.
    }
}
```
Wire an httpmock transport for the release asset URL returning a `httptest.Server` handler that keeps writing text bytes with `Transfer-Encoding: chunked` and never closes the body, then drive it through `downloadAsset`/`destinationWriter.Copy` with `isTTY=true` and `file: "-"`; observe process RSS grow without bound because no `LimitReader`/size cap exists in `pkg/iostreams/content.go` or `pkg/cmd/release/download/download.go`.

### Citations

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

**File:** pkg/cmd/release/download/download.go (L416-429)
```go
func (w destinationWriter) Copy(name string, r io.Reader) (copyErr error) {
	fp := w.makePath(name)
	if fp == "-" {
		if w.allowEscapes {
			_, copyErr = io.Copy(w.stdout, r)
			return
		}
		copyErr = iostreams.CopyGuardedContent(w.stdout, r, w.isTTY)
		if binErr, ok := errors.AsType[iostreams.BinaryTerminalError](copyErr); ok {
			copyErr = fmt.Errorf("%w; use `--output` to save it to a file, or pass --allow-escape-sequences to output it anyway", binErr)
		} else if errors.Is(copyErr, iostreams.ErrEscapeSequence) {
			copyErr = errors.New("the asset contains terminal escape sequences; use `--output` to save it to a file, or pass --allow-escape-sequences to output it anyway")
		}
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
