### Title
Unconfined path join lets a malicious release asset name write outside `--dir` via `filepath.Join` - ([File: pkg/cmd/release/download/download.go])

### Summary
`destinationWriter.makePath` builds the destination path with a raw `filepath.Join(w.dir, name)` where `name` comes directly from the attacker-controlled `release_asset.Name` field returned by the GitHub API. Unlike `gh run download`, which resolves artifact names through `safepaths.ParseAbsolute`/`Join` and rejects path-traversal, `gh release download` performs no confinement check on asset names before joining them into the destination path.

### Finding Description
`downloadRun` builds `downloadTarget{name: a.Name}` directly from `release.Assets` fetched from the GitHub API without validating or sanitizing `a.Name` [1](#0-0) [2](#0-1) . That name is passed into `downloadAsset`, which calls `dest.Check(fileName)` and later `dest.Copy(fileName, resp.Body)` [3](#0-2) [4](#0-3) .

Both `Check` and `Copy` resolve the write location via `makePath`, which does a bare `filepath.Join(w.dir, name)` with no confinement to `w.dir`: [5](#0-4) 

`filepath.Join` cleans `..` segments algebraically but does not prevent the result from escaping `w.dir` — e.g. `filepath.Join("/tmp/dest", "../evil.sh")` yields `/tmp/evil.sh`. `Copy` then creates any needed parent directories via `os.MkdirAll(filepath.Dir(fp), 0755)` and writes the file with `os.OpenFile(fp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)` [6](#0-5) , so both directory creation and file writing occur outside the user-specified `--dir` if the asset name contains traversal segments.

This is corroborated by contrast with the sibling artifact-download code path (`gh run download`), which explicitly guards against this exact class of bug: it parses the destination into a `safepaths.Absolute` and calls `.Join(a.Name)`, checking for `safepaths.PathTraversalError` and refusing the download if traversal would occur [7](#0-6) . No equivalent `safepaths` usage exists anywhere in `pkg/cmd/release/download/download.go`.

An unprivileged attacker can create a public repository and publish a release with an asset whose name is API-settable to a traversal string (GitHub's release-asset upload API accepts a `name` query parameter which is stored and returned as `release_asset.Name`). When a victim runs `gh release download <tag> -D <dir>` (or without `--pattern`, matching by default) against that repo, `downloadAsset` calls `dest.Copy(fileName, ...)` with the attacker-supplied name, and `makePath` resolves the write path outside `<dir>`.

### Impact Explanation
This is a file-write-outside-intended-path vulnerability. A victim invoking `gh release download` against an attacker's public repository, fork, or shared release could have a file written outside the directory they specified with `--dir`, e.g. into the current working directory or a parent directory relative to it, potentially clobbering existing files (e.g., dotfiles, shell rc files, or other startup files) if the traversal depth matches a writable location. This matches the "file write or overwrite outside the intended path" impact class in the bounty rules.

### Likelihood Explanation
Preconditions are minimal and fully within reach of an unprivileged attacker: publish any public repository, create a release, and attach/name an asset using a traversal string via the release asset creation API. The victim only needs to run an ordinary `gh release download` command against that repository/tag. No special privileges, admin rights, or token leakage are required, and the exploit is deterministic/repeatable on every download. The main uncertainty is whether GitHub's actual release-asset upload API server-side strips or rejects `/`/`..` in asset names — the `gh` CLI code itself does not perform any such client-side validation on the read/download path, so this depends on the API returning attacker-influenced names unsanitized, which I was not able to verify from this repository alone.

### Recommendation
Confine `makePath`'s output to `w.dir` the same way the artifact-download path does, e.g., use `internal/safepaths` (`safepaths.ParseAbsolute(w.dir)` then `.Join(name)`), returning a `PathTraversalError` (or equivalent explicit rejection) when the joined path would escape the destination directory, and surface a clear error to the user instead of writing the file.

### Proof of Concept
```go
// pkg/cmd/release/download/download_test.go (new test)
func TestDownloadAsset_PathTraversal(t *testing.T) {
    tmpDir := t.TempDir()
    dest := destinationWriter{dir: tmpDir}

    // Attacker-controlled asset name containing path traversal
    maliciousName := "../evil.sh"
    fp := dest.makePath(maliciousName)

    // Assert the resolved path stays within tmpDir; today it does NOT.
    absDest, _ := filepath.Abs(tmpDir)
    absFp, _ := filepath.Abs(fp)
    if !strings.HasPrefix(absFp, absDest+string(os.PathSeparator)) {
        t.Fatalf("path traversal: resolved path %q escapes destination %q", absFp, absDest)
    }
}
```
Full end-to-end reproduction: use `httpmock` to stub the release listing endpoint returning an asset with `"name": "../evil.sh"`, then call `downloadAssets`/`downloadAsset` with a `destinationWriter{dir: tmpDir}` and an httpmock'd asset-content response; assert that no file is created outside `tmpDir` (currently the test would show a file written at `filepath.Dir(tmpDir)/evil.sh`).

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

**File:** pkg/cmd/release/download/download.go (L300-303)
```go
func downloadAsset(dest *destinationWriter, httpClient *http.Client, assetURL safeurl.SafeURL, fileName string, isArchive bool) error {
	if err := dest.Check(fileName); err != nil {
		return err
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

**File:** pkg/cmd/release/download/download.go (L435-443)
```go
	if dir := filepath.Dir(fp); dir != "." {
		if copyErr = os.MkdirAll(dir, 0755); copyErr != nil {
			return
		}
	}

	var f *os.File
	if f, copyErr = os.OpenFile(fp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644); copyErr != nil {
		return
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
