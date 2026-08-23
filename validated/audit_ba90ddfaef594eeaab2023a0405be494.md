### Title
Path traversal in `gh release download` allows writing files outside `--dir` via crafted asset `name` - (File: `pkg/cmd/release/download/download.go`)

### Summary
`destinationWriter.makePath` builds the destination path with a plain `filepath.Join(w.dir, name)` and never validates that the resulting path stays within `w.dir`. Since `name` is populated directly from the Releases API `assets[].name` field, which is fully controlled by whoever owns the repository publishing the release, a malicious release asset name containing traversal segments (e.g. `../../.bashrc`) lets the attacker write to arbitrary locations reachable from `--dir` on the victim's machine.

### Finding Description
`downloadRun` builds `downloadTarget{name: a.Name}` directly from `release.Assets` returned by the GitHub API, with no sanitization of the `name` field beyond a Windows-reserved-name check and glob pattern matching: [1](#0-0) [2](#0-1) 

This flows into `downloadAsset(dest, httpClient, a.url, a.name, isArchive)` and then `dest.Copy(fileName, resp.Body)`: [3](#0-2) 

`Copy` calls `makePath(name)`, which does a raw `filepath.Join(w.dir, name)` with no check that the joined path remains inside `w.dir`: [4](#0-3) [5](#0-4) 

`filepath.Join` calls `filepath.Clean` internally, which resolves `..` segments lexically — it does not stop the result from escaping `w.dir`. For example, `filepath.Join("/home/victim/downloads", "../../.bashrc")` yields `/home/victim/.bashrc`. `MkdirAll` is then called on the resulting parent directory and `os.OpenFile` opens it with `O_CREATE|O_TRUNC`, meaning an existing file at that location is truncated and overwritten with attacker-supplied content.

Other download paths in this codebase (e.g. `internal/zip`, `internal/skills/installer`, `pkg/cmd/run/download`) reference traversal-prevention concepts (`safepaths`, zip-slip checks), but `pkg/cmd/release/download` has no equivalent guard on the asset `name` field before it is joined into a filesystem path.

### Impact Explanation
This is an unauthenticated (from the victim's perspective) arbitrary file write/overwrite vulnerability: an attacker who controls a public repository's release assets can cause `gh release download --dir <victim-controlled-dir>` to write or overwrite files outside the intended download directory. Depending on the victim's `--dir` choice (e.g. home directory) and OS, this could overwrite shell startup files (`.bashrc`, `.profile`), SSH config, or other files reachable via relative traversal from the download directory, potentially leading to code execution on next shell/login. This matches the "file write/overwrite outside intended path" impact class.

### Likelihood Explanation
- Precondition: victim must run `gh release download` (optionally with `--dir`) against a repository controlled by the attacker (a repo the attacker owns, or any public repo where the attacker can create releases — including forks).
- No token, admin, or MITM access is required — any GitHub user can create a repository and publish a release with an arbitrary asset filename via the API/UI, since GitHub does not reject `..`-containing asset names.
- The traversal depth is limited by the depth of `--dir` relative to the target file, but a sufficiently deep sequence of `../` segments can reach the filesystem root and target arbitrary absolute paths reachable from there.
- This is fully reproducible: no special network conditions, timing, or race conditions are needed.

### Recommendation
In `makePath` (or in `downloadRun` before building `downloadTarget`), sanitize the asset `name`:
- Reject or strip path separators and `..` segments from `name` (e.g., use `filepath.Base(name)` before joining, as is already done for the archive `Content-Disposition` filename case at line 344), or
- After computing `fp := filepath.Join(w.dir, name)`, verify with `filepath.Abs` + `filepath.Rel`/`strings.HasPrefix` (or reuse the existing `internal/safepaths` package used elsewhere in the codebase) that `fp` remains within the resolved `w.dir`, and return an error otherwise.

### Proof of Concept
```go
func TestDownloadRun_PathTraversalInAssetName(t *testing.T) {
    reg := &httpmock.Registry{}
    defer reg.Verify(t)

    reg.Register(
        httpmock.REST("GET", "repos/OWNER/REPO/releases/latest"),
        httpmock.JSONResponse(map[string]interface{}{
            "tag_name": "v1.0.0",
            "assets": []map[string]interface{}{
                {
                    "name": "../../evil.sh",
                    "url":  "https://api.github.com/assets/1234",
                    "api_url": "https://api.github.com/assets/1234",
                },
            },
        }),
    )
    reg.Register(
        httpmock.REST("GET", "assets/1234"),
        httpmock.StringResponse("malicious payload"),
    )

    tempDir := t.TempDir()
    subDir := filepath.Join(tempDir, "downloads")
    os.MkdirAll(subDir, 0755)

    opts := &DownloadOptions{
        HttpClient: func() (*http.Client, error) { return &http.Client{Transport: reg}, nil },
        IO:         iostreams.Test(),
        BaseRepo:   func() (ghrepo.Interface, error) { return ghrepo.New("OWNER", "REPO"), nil },
        Destination: subDir,
        Concurrency: 1,
    }

    err := downloadRun(opts)
    require.NoError(t, err)

    // Expected (secure) behavior: file should NOT exist outside subDir
    escapedPath := filepath.Join(tempDir, "evil.sh")
    _, statErr := os.Stat(escapedPath)
    require.True(t, os.IsNotExist(statErr), "asset should not be writable outside --dir, but was written to %s", escapedPath)
}
```
Expected result on the current code: the test fails because `evil.sh` is created at `tempDir/evil.sh`, outside the `subDir` passed via `--dir`, confirming the path traversal.

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

**File:** pkg/cmd/release/download/download.go (L300-351)
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
