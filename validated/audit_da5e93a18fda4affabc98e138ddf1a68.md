### Title
Unbounded response body written to disk with no maximum size check during `gh run download` artifact extraction, extension binary install, and release download - ([File: pkg/cmd/run/download/http.go])

### Summary
The reported DAOsis `invest()` bug is a missing "maximum allowed amount" check before an unbounded value is accumulated/persisted. The closest reachable analog in this `gh` CLI codebase is the family of download functions that stream an HTTP response body of attacker/remote-controlled size directly to disk (or into an in-memory `zip.Reader`) with no cap on content length, no `Content-Length` validation, and no limit on decompressed output size — mirroring "no check for a maximum" before committing an untrusted quantity.

### Finding Description
`downloadArtifact` in `pkg/cmd/run/download/http.go` fetches a workflow-run artifact ZIP and copies the entire response body into a temp file with a raw `io.Copy`, with no maximum size enforced: [1](#0-0) 

The resulting file is then opened as a `zip.Reader` and every entry is expanded via `extractZipFile`, which also performs an unbounded `io.Copy` from the decompressed entry stream to the destination file, with no check on decompressed size vs. compressed size (classic zip-bomb pattern) and no cumulative extraction size cap: [2](#0-1) 

The same unbounded-copy pattern recurs in the GitHub CLI extension installer, which downloads an extension release binary asset to disk with no size limit before execution as a subcommand: [3](#0-2) 

and in `gh release download`'s asset writer: [4](#0-3) 

In every case, only HTTP status code is checked; there is no verification against a `Content-Length` bound, no streaming size cap, and no post-hoc enforcement of a maximum byte count comparable to `tokensForSale` in the reference finding.

### Impact Explanation
A remote party that controls the artifact/asset/response content (e.g., a workflow run artifact producer, an extension repository owner, or a release asset uploader) can serve an arbitrarily large or highly-compressible payload. When the user runs `gh run download`, `gh extension install`, or `gh release download` against that repository, `gh` will write an unbounded amount of data to local disk, and in the artifact-download case will additionally decompress a zip bomb without any output-size guard. This can exhaust local disk space (denial of service) and, for extensions, results in fully unverified/unsized binaries being written and later executed as a `gh` subcommand.

### Likelihood Explanation
Reachability requires only a normal, unprivileged `gh` invocation against a repository/artifact/release that is not necessarily controlled by the invoking user (e.g., downloading artifacts from a CI run in a shared repo, or installing a third-party `gh` extension) — this matches the "extension install and execution" and "downloads to disk" categories called out as in-scope. No admin privilege, MITM, or leaked token is required; the attacker only needs to control the content served for the artifact/asset the victim chooses to download or install.

### Recommendation
Introduce an explicit maximum-size check (analogous to the missing `tokensForSale` cap) before and during these copy operations:
- Validate/limit based on `Content-Length` where present, and always wrap the response body in a limited reader (e.g., `io.LimitReader`) with a sane maximum, aborting if the limit is exceeded, in `downloadArtifact` (`pkg/cmd/run/download/http.go`), `downloadAsset` (`pkg/cmd/extension/http.go`), and `destinationWriter.Copy` (`pkg/cmd/release/download/download.go`).
- In `internal/zip/zip.go`'s `extractZipFile`, track and cap cumulative decompressed bytes (and per-file decompressed size vs. compressed size ratio) to prevent zip-bomb style disk exhaustion during extraction.

### Proof of Concept
1. Host (or control) a GitHub Actions run artifact, a `gh` extension release asset, or a release asset whose HTTP response returns a very large or highly compressible body (e.g., a zip file with a small compressed size but an enormous decompressed size).
2. Have the victim run `gh run download <run-id>`, `gh extension install <owner>/<repo>`, or `gh release download <tag>` against that artifact/extension/release.
3. Observe that `downloadArtifact`/`downloadAsset`/`destinationWriter.Copy` streams the entire response body via unbounded `io.Copy` (as shown above) with no maximum-size enforcement, and — for the artifact path — `extractZipFile` decompresses each zip entry via unbounded `io.Copy` with no output-size cap, allowing the local disk to be filled far beyond the size of the original network transfer.

Note: I could not find any existing size-limiting logic (`LimitReader`, max-size constant, or decompression ratio check) anywhere in these three download paths or in `internal/zip/zip.go`, confirming the absence of a maximum-size guard analogous to the missing `tokensForSale` check in the reference report.

### Citations

**File:** pkg/cmd/run/download/http.go (L41-68)
```go
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return api.HandleHTTPError(resp)
	}

	tmpfile, err := os.CreateTemp("", "gh-artifact.*.zip")
	if err != nil {
		return fmt.Errorf("error initializing temporary file: %w", err)
	}
	defer func() {
		_ = tmpfile.Close()
		_ = os.Remove(tmpfile.Name())
	}()

	size, err := io.Copy(tmpfile, resp.Body)
	if err != nil {
		return fmt.Errorf("error writing zip archive: %w", err)
	}

	zipfile, err := zip.NewReader(tmpfile, size)
	if err != nil {
		return fmt.Errorf("error extracting zip archive: %w", err)
	}
```

**File:** internal/zip/zip.go (L60-73)
```go
	var df *os.File
	if df, extractErr = os.OpenFile(dest.String(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, getPerm(zm)); extractErr != nil {
		return
	}

	defer func() {
		if err := df.Close(); extractErr == nil && err != nil {
			extractErr = err
		}
	}()

	_, extractErr = io.Copy(df, f)
	return
}
```

**File:** pkg/cmd/extension/http.go (L78-112)
```go
// downloadAsset downloads a single asset to the given file path.
func downloadAsset(httpClient *http.Client, assetURL safeurl.SafeURL, destPath string) (downloadErr error) {
	var req *http.Request
	if req, downloadErr = http.NewRequest("GET", assetURL.String(), nil); downloadErr != nil {
		return
	}

	req.Header.Set("Accept", "application/octet-stream")

	var resp *http.Response
	// TODO(api-client-rollout)
	// This has been deferred from moving to api.Client due to its custom Accept header and binary response streaming.
	if resp, downloadErr = httpClient.Do(req); downloadErr != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		downloadErr = api.HandleHTTPError(resp)
		return
	}

	var f *os.File
	if f, downloadErr = os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755); downloadErr != nil {
		return
	}
	defer func() {
		if err := f.Close(); downloadErr == nil && err != nil {
			downloadErr = err
		}
	}()

	_, downloadErr = io.Copy(f, resp.Body)
	return
}
```

**File:** pkg/cmd/release/download/download.go (L415-454)
```go
// Copy writes the data from r into a file specified by name.
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
	}
	if copyErr = w.check(fp); copyErr != nil {
		return
	}

	if dir := filepath.Dir(fp); dir != "." {
		if copyErr = os.MkdirAll(dir, 0755); copyErr != nil {
			return
		}
	}

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
}
```
