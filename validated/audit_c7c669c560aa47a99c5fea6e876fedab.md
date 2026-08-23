This confirms the vulnerability: `pkg/cmd/release/download/download.go` has no traversal protection, unlike the analogous `pkg/cmd/run/download` package which validated against exactly this issue.

### Title
Path traversal in `gh release download` via malicious asset name allows arbitrary file write outside `--dir` - ([File: pkg/cmd/release/download/download.go])

### Summary
`destinationWriter.makePath` builds the destination file path with a bare `filepath.Join(w.dir, name)`, where `name` is the attacker-controlled release asset `Name` field from the GitHub API. Unlike `pkg/cmd/run/download`, which uses `safepaths.Absolute.Join` and explicitly rejects traversal (returning `"would result in path traversal"`), the release download path performs no such check, allowing a malicious asset name like `../../.ssh/authorized_keys` to escape the destination directory.

### Finding Description
In `downloadRun`, assets come straight from `release.Assets` (populated via `shared.FetchRelease`/`shared.FetchLatestRelease` from the GitHub API) and are converted into `downloadTarget{name: a.Name}` without any sanitization of `a.Name` beyond an optional `--pattern` glob match and a Windows-reserved-name check [1](#0-0) . These are passed to `downloadAsset`, which calls `dest.Check(fileName)` and later `dest.Copy(fileName, resp.Body)` [2](#0-1) [3](#0-2) .

Both `Check` and `Copy` resolve the destination path via `makePath`: [4](#0-3) 

This is a raw `filepath.Join(w.dir, name)` with no confinement check — `filepath.Join` normalizes `..` segments but does not prevent the result from escaping `w.dir` (e.g., `filepath.Join("/tmp/out", "../../.ssh/authorized_keys")` resolves outside `/tmp/out`). `Copy` then calls `os.MkdirAll(filepath.Dir(fp), 0755)` and `os.OpenFile(fp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)` unconditionally on this unconfined path [5](#0-4) .

This is a clear regression/gap relative to the sibling command `gh run download`, which fixed exactly this class of bug: it parses the destination as a `safepaths.Absolute` and joins artifact names via `Absolute.Join`, which explicitly errors with a `PathTraversalError` if the join would escape the base directory [6](#0-5) [7](#0-6) . That package even has a regression test asserting `"error downloading ..: would result in path traversal"` for a malicious artifact name [8](#0-7) . The release-download code path has no equivalent test or protection — a search of `pkg/cmd/release/download/download_test.go` found no references to `makePath`, path traversal, or `..` handling at all.

The archive-download branch (`--archive zip/tar.gz`) constrains `fileName` via `filepath.Base(serverFileName)` when derived from `Content-Disposition` [9](#0-8) , but this sanitization does not apply to the normal per-asset `a.Name` path, which is the vulnerable one here.

### Impact Explanation
An attacker who publishes a public release with an asset named e.g. `../../.ssh/authorized_keys` (or a Windows UNC/relative-traversal equivalent) can cause `gh release download` to write attacker-controlled bytes to a path outside the victim's chosen `--dir`. This is an arbitrary file write outside the intended output directory, matching the GitHub bounty "file write outside the intended path" impact class. Depending on victim environment and permissions, this could clobber sensitive files (SSH authorized_keys, shell startup scripts, cron files, etc.), potentially escalating to code execution when combined with startup-file overwrite scenarios named in the prompt.

### Likelihood Explanation
High feasibility and fully unprivileged: any GitHub user can create a public repository and publish a release with an asset carrying an arbitrary `Name` field (GitHub's release asset upload API does not restrict the display name to a safe filename). The only precondition is that a victim runs `gh release download` (with any `--dir` or the default cwd) against that attacker's repo/tag — a very ordinary, commonly recommended operation for consuming release artifacts. No token, MITM, or social engineering beyond "download my release" is required.

### Recommendation
Mirror the `pkg/cmd/run/download` approach: parse `opts.Destination` into a `safepaths.Absolute` once, and in `destinationWriter.makePath`/`Copy`, join the asset name via `Absolute.Join` instead of `filepath.Join`, propagating a clear error (or skipping the asset) when a `safepaths.PathTraversalError` is returned. Additionally, consider stripping the name to `filepath.Base` (as already done for archive `Content-Disposition` filenames) before use as a defense-in-depth measure.

### Proof of Concept
Add a test to `pkg/cmd/release/download/download_test.go` analogous to the existing `pkg/cmd/run/download/download_test.go` traversal test:

```go
func TestDestinationWriter_MakePath_PathTraversal(t *testing.T) {
    tmpDir := t.TempDir()
    w := destinationWriter{dir: tmpDir}
    fp := w.makePath("../../evil.txt")
    // Currently fp resolves outside tmpDir - this assertion FAILS today,
    // demonstrating the vulnerability:
    require.True(t, strings.HasPrefix(fp, tmpDir),
        "expected path to remain under %s, got %s", tmpDir, fp)
}
```

Full end-to-end reproduction using httpmock (matching the pattern used elsewhere in `download_test.go` for `downloadRun`):
1. Stub the release API (`shared.FetchRelease`) to return a release with one asset: `Asset{Name: "../../evil.txt", APIURL: ".../assets/1"}`.
2. Stub the asset download to return arbitrary bytes.
3. Invoke `downloadRun` with `opts.Destination` set to a fresh `t.TempDir()` subdirectory (e.g., `tmpDir/out`).
4. Assert that no file was written under `tmpDir/out`, and that `evil.txt` was instead written to `tmpDir` (one level up) — proving escape from the intended `--dir`, mirroring the confinement assertion already used for `gh run download`.

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

**File:** pkg/cmd/release/download/download.go (L300-303)
```go
func downloadAsset(dest *destinationWriter, httpClient *http.Client, assetURL safeurl.SafeURL, fileName string, isArchive bool) error {
	if err := dest.Check(fileName); err != nil {
		return err
	}
```

**File:** pkg/cmd/release/download/download.go (L336-348)
```go
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
```

**File:** pkg/cmd/release/download/download.go (L350-350)
```go
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

**File:** pkg/cmd/run/download/download.go (L161-188)
```go
	absoluteDestinationDir, err := safepaths.ParseAbsolute(opts.DestinationDir)
	if err != nil {
		return fmt.Errorf("error parsing destination directory: %w", err)
	}

	for _, a := range artifacts {
		if a.Expired {
			continue
		}
		if downloaded.Contains(a.Name) {
			continue
		}
		if len(wantNames) > 0 || len(wantPatterns) > 0 {
			if !matchAnyName(wantNames, a.Name) && !matchAnyPattern(wantPatterns, a.Name) {
				continue
			}
		}

		destDir := absoluteDestinationDir
		if isolateArtifacts {
			destDir, err = absoluteDestinationDir.Join(a.Name)
			if err != nil {
				var pathTraversalError safepaths.PathTraversalError
				if errors.As(err, &pathTraversalError) {
					return fmt.Errorf("error downloading %s: would result in path traversal", a.Name)
				}
				return err
			}
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

**File:** pkg/cmd/run/download/download_test.go (L688-714)
```go
		{
			name: "handling artifact name with path traversal exploit",
			opts: DownloadOptions{
				RunID: "2345",
			},
			platform: &fakePlatform{
				runs: []run{
					{
						id: "2345",
						testArtifacts: []testArtifact{
							{
								artifact: shared.Artifact{
									Name:        "..",
									DownloadURL: "http://download.com/artifact1.zip",
									Expired:     false,
								},
								files: []string{
									"etc/passwd",
								},
							},
						},
					},
				},
			},
			expectedFiles: []string{},
			wantErr:       "error downloading ..: would result in path traversal",
		},
```
