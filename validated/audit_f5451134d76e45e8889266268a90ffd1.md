### Title
Path traversal via unsanitized asset name in `downloadAssets`/`destinationWriter.makePath` allows writes outside `--dir` - (File: pkg/cmd/release/download/download.go)

### Summary
`downloadAsset` passes the release asset's `Name` field (or, for archives, a server-supplied `Content-Disposition` filename) straight into `destinationWriter.makePath`, which builds the destination path with `filepath.Join(w.dir, name)` and no traversal check. Because a malicious or attacker-controlled API response can set an asset name containing `../` sequences, `gh release download` can be made to write files outside the user-specified `--dir`.

### Finding Description
`downloadRun` builds `downloadTarget{url, name: a.Name}` directly from `release.Assets` returned by the GitHub API (`pkg/cmd/release/download/download.go:238-243`), with the only prior filtering being pattern matching and a Windows-reserved-name check (`download.go:196-207`) — neither of which rejects `..` or path separators. This flows into `downloadAsset` (`download.go:300`), which calls `dest.Check(fileName)` and `dest.Copy(fileName, ...)`.

`destinationWriter.makePath` (`download.go:379-384`) computes the final path as `filepath.Join(w.dir, name)`. `filepath.Join` only cleans the resulting path; it does not prevent `..` components from escaping `w.dir`. For example, `filepath.Join("dest", "../../etc/foo")` cleans to `../etc/foo`, i.e., outside `dest`. `Copy` (`download.go:416-454`) then calls `os.MkdirAll(filepath.Dir(fp), 0755)` and `os.OpenFile(fp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)`, creating/overwriting the file at the escaped path.

The same unsanitized pattern applies to archive downloads: when `fileName` is empty, `downloadAsset` derives it from the `Content-Disposition` header via `filepath.Base(serverFileName)` (`download.go:344`), which *is* sanitized with `filepath.Base`, closing that particular avenue — but the primary named-asset path (`a.Name`) has no equivalent `filepath.Base`/traversal check. The `--output`/`-O` code path is unaffected because it uses `w.file` verbatim, but the `--dir` (default) path is exposed to the untrusted `name`.

This matches the invariant violation named in the target: "the destination root comes from the user; remote names contribute only sanitized leaf elements" is false here — the remote name is joined without sanitization and can contain traversal components that escape the "leaf" position entirely.

### Impact Explanation
An attacker who can influence a release's asset name (e.g., a repository owner/maintainer publishing a release with a crafted asset name such as `../../../../.bashrc` or, more critically, one reachable from a GHES/enterprise host or a spoofed API response returned to `gh --hostname`) can cause `gh release download` to write attacker-controlled bytes to an arbitrary path outside the destination directory relative to the current working directory. Overwriting shell startup files, git hooks, or other config controlled by the victim can escalate to arbitrary code execution the next time the victim opens a shell or runs `git`. This matches the "Arbitrary file write/overwrite outside intended directory, escalating to code execution" impact class described in the target.

### Likelihood Explanation
Exploitability depends on whether the asset `Name` field can actually contain path-traversal characters when returned to the client. GitHub.com's release-asset upload API may itself restrict filenames server-side (not verified in this repo, since that enforcement — if any — lives entirely outside this codebase). However, the `gh` CLI here performs no client-side check on `a.Name`, so any host or endpoint the victim points `gh` at (GHES instance, or an attacker able to influence the JSON response) can trivially supply a hostile name, and the CLI would honor it without complaint. Given the code performs no defensive `filepath.Base`/traversal check itself, the vulnerability is real irrespective of GitHub.com's own upload validation, and is fully reachable via the standard `gh release download` command.

### Recommendation
In `destinationWriter.makePath` (and/or in `downloadRun` when building `downloadTarget`), reject or sanitize asset names before joining: use `filepath.Base(name)` to reduce to a single path element, and/or verify with something like `filepath.IsLocal(name)` (Go 1.20+) or an explicit check that the cleaned relative path does not begin with `..` or contain a path separator, returning an error such as `"asset %q has an unsafe file name"` instead of silently allowing the join.

### Proof of Concept
```go
func TestDestinationWriter_PathTraversal(t *testing.T) {
    dir := t.TempDir()
    dw := destinationWriter{dir: dir}

    // simulate a release asset whose Name field is attacker-controlled
    maliciousName := "../evil.txt"

    fp := dw.makePath(maliciousName)

    // Assert the resolved path stays within dir; currently it does not.
    rel, err := filepath.Rel(dir, fp)
    if err != nil || strings.HasPrefix(rel, "..") {
        t.Fatalf("path escaped destination directory: dir=%s resolved=%s", dir, fp)
    }
}
```
Running this against the current implementation demonstrates `fp` resolves outside `dir` (e.g., to the parent of `t.TempDir()`), confirming that `downloadAssets` → `destinationWriter.Copy` would create/overwrite a file outside the user-specified `--dir` if `Name` (`a.Name` in `download.go:241`) contains `..` segments. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** pkg/cmd/release/download/download.go (L196-207)
```go
		for _, a := range release.Assets {
			if len(opts.FilePatterns) > 0 && !matchAny(opts.FilePatterns, a.Name) {
				continue
			}
			// Note that if we need to start checking for reserved filenames on
			// more operating systems we should move to using a build constraints
			// pattern rather than checking the operating system at runtime.
			if runtime.GOOS == "windows" && isWindowsReservedFilename(a.Name) {
				return fmt.Errorf("unable to download release due to asset with reserved filename %q", a.Name)
			}
			toDownload = append(toDownload, a)
		}
```

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

**File:** pkg/cmd/release/download/download.go (L300-350)
```go
func downloadAsset(dest *destinationWriter, httpClient *http.Client, assetURL safeurl.SafeURL, fileName string, isArchive bool) error {
	if err := dest.Check(fileName); err != nil {
		return err
	}

	req, err := http.NewRequest("GET", assetURL.String(), nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/octet-stream")
	if isArchive {
		// adding application/json to Accept header due to a bug in the zipball/tarball API endpoint that makes it mandatory
		req.Header.Set("Accept", "application/octet-stream, application/json")

		// override HTTP redirect logic to avoid "legacy" Codeload resources
		oldClient := *httpClient
		httpClient = &oldClient
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) == 1 {
				req.URL.Path = removeLegacyFromCodeloadPath(req.URL.Path)
			}
			return nil
		}
	}

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

**File:** pkg/cmd/release/download/download.go (L379-384)
```go
func (w destinationWriter) makePath(name string) string {
	if w.file == "" {
		return filepath.Join(w.dir, name)
	}
	return w.file
}
```

**File:** pkg/cmd/release/download/download.go (L416-454)
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

**File:** pkg/cmd/release/shared/fetch.go (L73-87)
```go
type ReleaseAsset struct {
	ID     string `json:"node_id"`
	Name   string
	Label  string
	Size   int64
	Digest *string
	State  string
	APIURL string `json:"url"`

	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	DownloadCount      int       `json:"download_count"`
	ContentType        string    `json:"content_type"`
	BrowserDownloadURL string    `json:"browser_download_url"`
}
```
