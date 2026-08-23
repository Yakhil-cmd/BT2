Confirmed: no sanitization exists anywhere in this path. `Release`/`ReleaseAsset` are decoded directly from JSON via `json.NewDecoder(resp.Body).Decode(&release)` in `fetchReleasePath` with no name validation, and `a.Name` flows unmodified into `downloadTarget.name` and then into `destinationWriter.makePath` which does a bare `filepath.Join(w.dir, name)` with no `filepath.Base`, `filepath.Clean`+prefix-check, or rejection of `..`/absolute paths.### Title
Path traversal via unsanitized release asset `Name` in `gh release download` - (pkg/cmd/release/download/download.go)

### Summary
`gh release download` writes each release asset to a path built by naively joining the attacker-controlled `Name` field of `shared.ReleaseAsset` (from the JSON API response) with the destination directory, with no rejection of `..` segments or absolute paths. This allows a malicious release asset name to write files outside the intended `--destination`/current directory on the victim's machine.

### Finding Description
`downloadRun` builds `toDownload` from `release.Assets`, and for each asset copies `a.Name` verbatim into `downloadTarget.name` (no sanitization, only filtering by `--pattern` and Windows reserved-name check): [1](#0-0) [2](#0-1) 

The asset name comes straight from the JSON API response decoded in `fetchReleasePath`, which does a raw `json.NewDecoder(resp.Body).Decode(&release)` with no field validation: [3](#0-2) [4](#0-3) 

The name then reaches `destinationWriter.makePath`, which does a bare `filepath.Join(w.dir, name)` with no `filepath.Base`, no `filepath.Clean` + prefix-containment check, and no rejection of `..` components or absolute paths (only the Windows-archive-derived filename path uses `filepath.Base`, not the normal per-asset path): [5](#0-4) 

That path is then used unchanged by `Check`/`Copy`, including `os.MkdirAll` on the parent directory and `os.OpenFile(..., O_CREATE|O_TRUNC, ...)`, so an attacker-chosen name like `../../../.ssh/authorized_keys` (or, on Windows, a name containing `..\..\`) resolves outside `opts.Destination`, and directories along that traversal path are auto-created: [6](#0-5) 

No allowlist/safepaths mechanism exists on this code path — `safeurl` is only used for the API/asset request URL, not for the filesystem destination path.

### Impact Explanation
This is an arbitrary file write outside the intended destination directory, triggered simply by running `gh release download <tag>` against a release the attacker controls/publishes (or whose response the victim's `gh` otherwise consumes). Depending on target path chosen by the attacker, this can lead to overwriting sensitive files (e.g., shell profile files, SSH `authorized_keys`, cron files) reachable by the OS user running `gh`, which can escalate to code execution on subsequent shell/login. This matches a "file write outside the intended path" impact class.

### Likelihood Explanation
Preconditions: the victim must run `gh release download` (without a `--pattern` that would exclude the crafted name) against a release whose asset list contains attacker-controlled `name` values. The attacker is an unprivileged remote actor who "publishes ... releases," matching the threat model. One caveat not fully verifiable from this codebase alone: GitHub's real release-asset upload API may itself restrict characters like `/` in uploaded asset filenames, which would reduce practical exploitability against the real github.com API; however, for GitHub Enterprise Server or any host the victim points `gh` at (which the attacker-controlled-response threat model explicitly includes for "host the victim points gh at"), or via any GraphQL/REST response manipulation before this stricter validation, the raw JSON field is trusted as-is by this client code with zero defense-in-depth. Regardless of upstream API restrictions, the CLI itself performs no validation, so it is not defended even against a future or alternate API surface (e.g., a compromised/malicious enterprise server) that permits such names.

### Recommendation
In `destinationWriter.makePath` (or in `downloadRun` when building `toDownload`), reject or sanitize asset names before joining: use `filepath.Base(name)` to strip any directory components, and/or resolve `filepath.Join(w.dir, name)` then verify the resulting cleaned path has `w.dir` (also cleaned/absolute) as a prefix, rejecting the operation otherwise (similar to standard zip-slip mitigations). This should apply uniformly to both the archive-derived filename (already using `filepath.Base`) and the normal per-asset name path.

### Proof of Concept
Unit test on `destinationWriter.Copy`:
```go
func TestDestinationWriter_Copy_PathTraversal(t *testing.T) {
    tmp := t.TempDir()
    outsideMarker := filepath.Join(filepath.Dir(tmp), "evil-traversal-poc.txt")
    defer os.Remove(outsideMarker)

    w := destinationWriter{dir: tmp}
    err := w.Copy("../evil-traversal-poc.txt", strings.NewReader("pwned"))
    assert.NoError(t, err) // currently succeeds — demonstrates the bug

    _, statErr := os.Stat(outsideMarker)
    assert.NoError(t, statErr, "file was written outside destination directory")
}
```
Integration-level PoC via `downloadRun` with `httpmock`:
```go
shared.StubFetchRelease(t, reg, "OWNER", "REPO", "v1.2.3", `{
  "assets": [
    { "name": "../../evil.txt", "size": 5,
      "url": "https://api.github.com/assets/9999" }
  ],
  "tarball_url": "...", "zipball_url": "..."
}`)
reg.Register(httpmock.REST("GET", "assets/9999"), httpmock.StringResponse("pwned"))
// opts.Destination = "<tempdir>/sub"
// after downloadRun(opts): assert file exists at "<tempdir>/../evil.txt" (i.e. outside "<tempdir>/sub")
```
Expected (fixed) behavior: `Copy`/`makePath` should return an error (or clamp the path) instead of writing outside `w.dir`.

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

**File:** pkg/cmd/release/download/download.go (L237-243)
```go
	targets := make([]downloadTarget, len(toDownload))
	for i, a := range toDownload {
		targets[i] = downloadTarget{
			url:  safeurl.NewImmutableSafeURL(a.APIURL),
			name: a.Name,
		}
	}
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

**File:** pkg/cmd/release/shared/fetch.go (L281-306)
```go
func fetchReleasePath(ctx context.Context, httpClient *http.Client, url safeurl.SafeURL) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, ErrReleaseNotFound
	} else if resp.StatusCode > 299 {
		return nil, api.HandleHTTPError(resp)
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	return &release, nil
}
```
