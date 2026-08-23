### Title
Path traversal via unsanitized release asset `Name` in `destinationWriter.makePath` allows arbitrary file write outside `--dir` destination - (File: pkg/cmd/release/download/download.go)

### Summary
`gh release download` builds the local file path for each asset by joining the attacker-controlled `shared.ReleaseAsset.Name` field directly with `filepath.Join(w.dir, name)` in `destinationWriter.makePath`, with no use of `safepaths.Absolute`/`filepath.Base` sanitization that the equivalent artifact-download code path (`pkg/cmd/run/download/http.go` + `internal/zip.ExtractZip`) already applies. A release asset named e.g. `../../../../.ssh/authorized_keys` therefore resolves outside the intended destination directory when the victim runs `gh release download`.

### Finding Description
`downloadRun` populates `downloadTarget.name` straight from `a.Name` (the JSON `name` field of a `shared.ReleaseAsset`) without any sanitization: [1](#0-0) . This flows to `downloadAsset(dest, httpClient, a.url, a.name, isArchive)` [2](#0-1) , which calls `dest.Check(fileName)` and then `dest.Copy(fileName, resp.Body)` [3](#0-2) .

Both `Check` and `Copy` route through `makePath`, which does a raw `filepath.Join(w.dir, name)` with no confinement check: [4](#0-3) . `filepath.Join` cleans `..` segments arithmetically but does not prevent the result from escaping `w.dir` — a name of `../../../../.ssh/authorized_keys` (or a Windows path like `..\..\AppData\Startup\evil.bat`) will produce a path outside `opts.Destination`. `Copy` then creates any missing parent directories via `os.MkdirAll(dir, 0755)` and writes the file with `os.OpenFile(..., os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)` [5](#0-4) , with no re-validation that `fp` remains inside `w.dir`.

By contrast, the codebase already has a purpose-built defense for exactly this class of bug: `internal/safepaths.Absolute.Join` explicitly rejects joins that would traverse outside the base directory, returning a `PathTraversalError` [6](#0-5) . This is used in the artifact-download path (`gh run download`), where `downloadArtifact` receives a `safepaths.Absolute` destination and delegates final path handling to `ghzip.ExtractZip`, and elsewhere (e.g., `internal/skills/installer`, `internal/zip`, `pkg/cmd/copilot/copilot.go`). The release-download code path never adopts this protection — `makePath` performs no traversal check and no `filepath.Base(name)` truncation, so the only current guard (`isWindowsReservedFilename`, which merely blocks Windows-reserved device names) does nothing to stop path traversal.

The attacker precondition is that they control `release.Assets[i].Name` returned by the API for a public repo/release they publish, and the victim runs `gh release download` (with no `--output` override, since `--output` takes a different, single-file code path) against that repo/tag, optionally matching via `--pattern`.

### Impact Explanation
This is an arbitrary file write/overwrite outside the intended destination directory, controlled entirely by the attacker via the release asset name and the victim's download command. On Linux this can overwrite files like `~/.ssh/authorized_keys`; on Windows, files under `AppData\Startup`, enabling persistence/code execution on next login. This matches GitHub's bounty impact class of "arbitrary file write/overwrite outside destination," and can escalate to code execution depending on the overwritten file's role (e.g., startup script, SSH keys, shell profile).

### Likelihood Explanation
Feasibility is high and requires no special privileges: any GitHub user can create a public repository, publish a release, and attach/rename an asset. If the release-asset upload API on the actual GitHub platform restricts `/` or `..` in the visible asset `name` field, this reduces exploitability against real GitHub.com but the CLI code itself provides no defense-in-depth check, so any host or API response that supplies such a name (including GHES or a compromised/malicious mirror the victim points `gh` at) will trigger the write. The victim simply needs to run an ordinary `gh release download` (or with `--pattern`) against the attacker's tag/release — a very common workflow. No `--output` flag is required (which would divert to a different code path), and the current `isWindowsReservedFilename` check does not address traversal at all.

### Recommendation
Sanitize/confine the asset filename before use in `makePath`: reject or clamp any name containing path separators or `..` components (e.g., via `filepath.Base(name)` for defense-in-depth, or preferably adopt `internal/safepaths.Absolute.Join`, mirroring the pattern already used by `pkg/cmd/run/download` and `internal/zip.ExtractZip`), returning an error rather than silently truncating when a traversal attempt is detected. Add tests analogous to the artifact-download `isolateArtifacts` coverage that assert traversal names are rejected instead of written outside the destination.

### Proof of Concept
```go
func Test_downloadRun_PathTraversal(t *testing.T) {
    reg := &httpmock.Registry{}
    defer reg.Verify(t)
    reg.Register(
        httpmock.REST("GET", "repos/OWNER/REPO/releases/tags/v1.0"),
        httpmock.JSONResponse(shared.Release{
            TagName: "v1.0",
            Assets: []shared.ReleaseAsset{
                {
                    Name:   "../../evil.txt", // or "..\\..\\AppData\\Startup\\evil.bat" on windows
                    APIURL: "https://api.github.com/assets/1234",
                },
            },
        }),
    )
    reg.Register(
        httpmock.REST("GET", "assets/1234"),
        httpmock.StringResponse("pwned"),
    )

    tempDir := t.TempDir()
    destDir := filepath.Join(tempDir, "dest")
    require.NoError(t, os.MkdirAll(destDir, 0755))

    opts := &DownloadOptions{
        TagName:     "v1.0",
        Destination: destDir,
        Concurrency: 1,
        HttpClient:  func() (*http.Client, error) { return &http.Client{Transport: reg}, nil },
        BaseRepo:    func() (ghrepo.Interface, error) { return ghrepo.New("OWNER", "REPO"), nil },
        IO:          iostreams.Test(),
    }

    err := downloadRun(opts)
    require.NoError(t, err)

    // Expected (secure) behavior: error or file confined to destDir.
    // Actual (vulnerable) behavior: file lands OUTSIDE destDir.
    escapedPath := filepath.Join(tempDir, "evil.txt")
    _, statErr := os.Stat(escapedPath)
    assert.NoError(t, statErr, "asset should not have been written outside destination directory")
}
```
Expected assertion for a fixed implementation: `downloadRun` returns an error (path traversal rejected) or the file is confined strictly under `destDir`; currently the file is created at `escapedPath`, outside `t.TempDir()`'s intended destination, demonstrating the vulnerability.

### Citations

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

**File:** pkg/cmd/release/download/download.go (L276-278)
```go
			for a := range jobs {
				io.StartProgressIndicatorWithLabel(fmt.Sprintf("Downloading %s", a.name))
				results <- downloadAsset(dest, httpClient, a.url, a.name, isArchive)
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

**File:** pkg/cmd/release/download/download.go (L431-452)
```go
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
```

**File:** internal/safepaths/absolute.go (L35-57)
```go
// Join an absolute path with elements to create a new Absolute path, or error.
// A PathTraversalError will be returned if the joined path would traverse outside of
// the base Absolute path. Note that this does not handle symlinks.
func (a Absolute) Join(elem ...string) (Absolute, error) {
	joinedAbsolutePath, err := ParseAbsolute(filepath.Join(append([]string{a.path}, elem...)...))
	if err != nil {
		return Absolute{}, fmt.Errorf("failed to parse joined path: %w", err)
	}

	isSubpath, err := joinedAbsolutePath.isSubpathOf(a)
	if err != nil {
		return Absolute{}, err
	}

	if !isSubpath {
		return Absolute{}, PathTraversalError{
			Base:  a,
			Elems: elem,
		}
	}

	return joinedAbsolutePath, nil
}
```
