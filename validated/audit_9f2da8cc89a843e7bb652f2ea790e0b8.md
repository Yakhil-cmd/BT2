### Title
Path traversal via unsanitized release asset `Name` in `destinationWriter.makePath` - ([File: pkg/cmd/release/download/download.go])

### Summary
When downloading named release assets (i.e., not through `--archive`), `downloadRun` passes `asset.Name` straight through to `downloadAsset`/`destinationWriter.Copy`/`makePath` with no path sanitization. `filepath.Join(w.dir, name)` does not confine the result to `w.dir`, so a release asset whose `Name` contains `../` sequences can cause `gh release download` to write outside the destination directory. This differs from the Content-Disposition-derived filename path (archive downloads), which does call `filepath.Base` before use.

### Finding Description
In `downloadRun`, assets from `release.Assets` are converted into `downloadTarget{name: a.Name}` with no sanitization: [1](#0-0) 

`a.Name` comes directly from the GitHub API's release asset metadata (`shared.ReleaseAsset`), which is attacker-controlled: a repository owner (unprivileged attacker) can publish a release with an asset whose `name` field contains path traversal sequences such as `../../.ssh/authorized_keys`.

This name flows into `downloadAsset(dest, httpClient, a.url, a.name, isArchive)` as `fileName`, and because `fileName` is non-empty, the Content-Disposition branch (which does apply `filepath.Base`) is skipped entirely: [2](#0-1) 

The unsanitized name is then passed to `dest.Check(fileName)` and `dest.Copy(fileName, resp.Body)`, both of which call `makePath`: [3](#0-2) 

`makePath` uses `filepath.Join(w.dir, name)`, which cleans `..` segments but does **not** confine the resulting path to `w.dir` — a `name` of `../../.ssh/authorized_keys` simply walks up from `w.dir` and joins the remainder, producing a path outside the intended destination. There is no check anywhere in `Check`, `check`, or `Copy` that the resulting `fp` remains a descendant of `w.dir`: [4](#0-3) 

Note that `allowEscapes` (the `AllowEscapeSequences` / `--allow-escape-sequences` flag) is unrelated to path confinement at all — it only guards whether escape sequences/binary content may be written to the stdout terminal in the `fp == "-"` branch of `Copy`: [5](#0-4) 
So there is no `allowEscapes`-gated path-confinement logic to bypass; the vulnerability is simply that path confinement is never implemented for asset-name-derived paths, regardless of any flag's value.

The only place filenames are sanitized with `filepath.Base` is the fallback branch used exclusively when `fileName` is empty (i.e., archive downloads with no explicit asset name), which named-asset downloads never hit: [6](#0-5) 

### Impact Explanation
A malicious repository/release owner can craft a release asset with `name` set to a path-traversal string. When a victim runs `gh release download` (or `gh release download --pattern` without narrowing enough, or specifically targeting that asset) against the attacker's repo, the downloaded file content is written to an attacker-chosen path outside the `--dir`/`Destination` directory, reachable by the invoking user (e.g., overwriting `~/.ssh/authorized_keys`, shell rc files, or other files the user can write to). This is a file write outside the intended path / potential privilege or account compromise depending on target file.

### Likelihood Explanation
- The attacker needs no special privileges beyond publishing a release in their own repository (or a repository the victim is instructed/tricked into downloading from), which is trivially available to any GitHub user.
- The victim must run an ordinary `gh release download` command against that repo — a common, expected workflow.
- Whether GitHub's release-asset upload API enforces server-side sanitization of the `name` field (e.g., stripping `/`) is not verified from this codebase alone; if GitHub's API allows arbitrary characters including `/` and `..` in asset names, this is directly exploitable client-side with no additional bypass needed, since `gh`'s client code performs no sanitization on `a.Name` at all before use in path construction.

### Recommendation
In `destinationWriter.makePath` (or before calling `Check`/`Copy`), sanitize the asset-derived `name` the same way the Content-Disposition fallback does — call `filepath.Base(name)` (or better, an explicit path-confinement check that resolves `filepath.Join(w.dir, name)`, cleans it, and verifies it remains prefixed by the cleaned `w.dir`) before using it to build the destination path. Apply this uniformly regardless of whether `fileName` originated from `asset.Name` or from `Content-Disposition`.

### Proof of Concept
```go
func TestDestinationWriter_MakePath_RejectsTraversal(t *testing.T) {
    dir := t.TempDir()
    w := destinationWriter{dir: dir}
    fp := w.makePath("../../../tmp/pwned")
    // Expect fp to remain rooted under dir; currently it does not.
    rel, err := filepath.Rel(dir, fp)
    require.NoError(t, err)
    require.False(t, strings.HasPrefix(rel, ".."), "path escaped destination dir: %s", fp)
}
```
Integration-style PoC: use `httpmock` to return a release with `assets: [{name: "../../../tmp/pwned", url: "...", ...}]`, run `downloadRun` with `Destination` set to a temp dir, then assert that no file was created at `<tempdir>/tmp/pwned` outside the temp dir tree — currently this assertion would fail because the file is written outside `Destination`.

### Citations

**File:** pkg/cmd/release/download/download.go (L196-208)
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
	}
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
