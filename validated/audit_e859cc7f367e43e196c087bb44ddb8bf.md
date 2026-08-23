### Title
Path traversal via release asset `Name` allows arbitrary file overwrite in `gh release download` - ([File: pkg/cmd/release/download/download.go])

### Summary
`gh release download` builds destination file paths with `filepath.Join(w.dir, name)` in `destinationWriter.makePath`, where `name` comes directly from the GitHub API's release asset `Name` field, with no traversal or absolute-path validation. This is inconsistent with the CLI's own established pattern (`internal/safepaths.Absolute.Join`) used in the analogous `gh run download` and skill/copilot extraction code paths, which explicitly guard against this exact attack.

### Finding Description
In `downloadRun`, assets are read from `release.Assets` and each asset's `a.Name` is passed unmodified into `downloadTarget.name` [1](#0-0) . This flows through `downloadAssets` → `downloadAsset` → `dest.Check(fileName)` / `dest.Copy(fileName, body)` [2](#0-1) [3](#0-2) , both of which call `makePath`:

```go
func (w destinationWriter) makePath(name string) string {
	if w.file == "" {
		return filepath.Join(w.dir, name)
	}
	return w.file
}
``` [4](#0-3) 

`filepath.Join` normalizes `..` segments but does not confine the result to `w.dir`; a name like `../../.ssh/authorized_keys` resolves to a path outside the destination directory. The resulting path is then used directly for `os.Stat` (in `check`) and `os.OpenFile(fp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)` in `Copy` [5](#0-4) , which will create parent directories via `os.MkdirAll(dir, 0755)` and overwrite/create the target file with attacker-supplied content.

Notably, the codebase already has a purpose-built defense for exactly this class of bug — `internal/safepaths.Absolute.Join`, which returns a `PathTraversalError` if the joined path would escape the base directory [6](#0-5) . This is used in the sibling `gh run download` command (artifact names from the Actions API) [7](#0-6) , in zip extraction (`internal/zip/zip.go`) [8](#0-7) , in `copilot.go`'s tar/zip extraction [9](#0-8) , and in the skills installer [10](#0-9) . There is even an explicit regression test in `pkg/cmd/run/download/download_test.go` proving the artifact-name traversal case is blocked there [11](#0-10) . `pkg/cmd/release/download/download.go` is the outlier: it never imports or uses `safepaths`, and `makePath` performs a raw `filepath.Join` with no post-check that the result stays under `w.dir`.

### Impact Explanation
An attacker who publishes a public release (fully within the reach of "an unprivileged attacker who publishes a GitHub release") can name an asset `../../.ssh/authorized_keys`, `../../../.bashrc`, or similar. If a victim runs `gh release download` (without a `--pattern` that happens to exclude the crafted name) against that repository/release, the tool will write attacker-controlled bytes to a file path outside the intended download directory, up the victim's directory tree from wherever `gh` is invoked. This is an arbitrary file write/overwrite primitive that can lead to persistence (e.g., overwriting `~/.bashrc`, `~/.ssh/authorized_keys`, or similar dotfiles reachable via relative traversal) and potential code execution depending on what gets overwritten. This matches GitHub's bounty impact class of "file write/overwrite outside the intended path."

### Likelihood Explanation
- Precondition: attacker needs a public repo with a release and an asset whose `name` metadata contains `..` path segments. GitHub's release asset upload API is known to accept unusual name strings from the uploading party at upload time (this is asserted as a precondition in the question and is consistent with how `filepath.Base` is applied elsewhere in this same file only for the archive-fallback filename derived from `Content-Disposition`, but not for named assets - see line 344 vs the untouched `a.Name` at line 241).
- Victim runs plain `gh release download [tag]` without narrowing via `--pattern`, which is a common, default usage pattern shown in the command's own examples (`$ gh release download v1.2.3`) [12](#0-11) .
- No user interaction beyond running the download command is required; no admin/org rights, no token leak, no MITM needed.
- Repeatable: deterministic based on asset name content.

### Recommendation
Use `internal/safepaths.Absolute` in `destinationWriter`, mirroring `pkg/cmd/run/download/download.go`: resolve `w.dir` once via `safepaths.ParseAbsolute`, and replace the raw `filepath.Join` in `makePath` with `absDir.Join(name)`, propagating/rejecting on `safepaths.PathTraversalError` (returning a clear error to the user, e.g., `"asset name %q would result in path traversal"`) instead of silently writing outside the destination.

### Proof of Concept
Add a test analogous to the existing `pkg/cmd/run/download/download_test.go` "handling artifact name with path traversal exploit" case, but for `pkg/cmd/release/download`:

```go
func Test_downloadRun_pathTraversal(t *testing.T) {
	reg := &httpmock.Registry{}
	defer reg.Verify(t)
	reg.Register(
		httpmock.REST("GET", "repos/OWNER/REPO/releases/tags/v1.2.3"),
		httpmock.JSONResponse(map[string]interface{}{
			"tag_name": "v1.2.3",
			"assets": []map[string]interface{}{
				{
					"name": "../../evil.txt",
					"url":  "https://api.github.com/assets/1234",
				},
			},
		}),
	)
	reg.Register(
		httpmock.REST("GET", "assets/1234"),
		httpmock.StringResponse("pwned"),
	)

	tmpdir := t.TempDir()
	destDir := filepath.Join(tmpdir, "downloads")
	require.NoError(t, os.MkdirAll(destDir, 0755))

	opts := &DownloadOptions{
		TagName:     "v1.2.3",
		Destination: destDir,
		Concurrency: 1,
		// ... IO, HttpClient, BaseRepo wired to reg as in existing tests
	}

	err := downloadRun(opts)
	require.NoError(t, err) // currently succeeds — this is the bug

	// Expected (post-fix) assertion: file must NOT exist outside destDir
	_, statErr := os.Stat(filepath.Join(tmpdir, "evil.txt"))
	require.True(t, os.IsNotExist(statErr), "path traversal file should not have been written outside destination")
}
```

Currently this test would show `evil.txt` written at `tmpdir/evil.txt` (one level above `destDir`), confirming the traversal. After applying the `safepaths.Absolute` fix, `downloadRun` should return a path-traversal error instead, and no file should be created outside `destDir`.

### Citations

**File:** pkg/cmd/release/download/download.go (L62-64)
```go
		Example: heredoc.Doc(`
			# Download all assets from a specific release
			$ gh release download v1.2.3
```

**File:** pkg/cmd/release/download/download.go (L238-243)
```go
	for i, a := range toDownload {
		targets[i] = downloadTarget{
			url:  safeurl.NewImmutableSafeURL(a.APIURL),
			name: a.Name,
		}
	}
```

**File:** pkg/cmd/release/download/download.go (L300-303)
```go
func downloadAsset(dest *destinationWriter, httpClient *http.Client, assetURL safeurl.SafeURL, fileName string, isArchive bool) error {
	if err := dest.Check(fileName); err != nil {
		return err
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

**File:** pkg/cmd/release/download/download.go (L416-417)
```go
func (w destinationWriter) Copy(name string, r io.Reader) (copyErr error) {
	fp := w.makePath(name)
```

**File:** pkg/cmd/release/download/download.go (L435-452)
```go
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

**File:** pkg/cmd/run/download/download.go (L179-189)
```go
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
		}
```

**File:** internal/zip/zip.go (L24-33)
```go
func ExtractZip(zr *zip.Reader, destDir safepaths.Absolute) error {
	for _, zf := range zr.File {
		fpath, err := destDir.Join(zf.Name)
		if err != nil {
			var pathTraversalError safepaths.PathTraversalError
			if errors.As(err, &pathTraversalError) {
				continue
			}
			return err
		}
```

**File:** pkg/cmd/copilot/copilot.go (L385-401)
```go
	absPath, err := safepaths.ParseAbsolute(destDir)
	if err != nil {
		return err
	}

	// As of the time of writing, ghzip.ExtractZip will safely skip files that
	// would result in path traversal. This is an issue for our use-case because
	// we want to error out before extracting if there's any such file.
	// To avoid breaking the shared ghzip.ExtractZip code that expects unsafe
	// paths to be ignored and no error produced, we pre-validate here,
	// producing an error if any such file is found.
	for _, f := range zipReader.File {
		_, err := absPath.Join(f.Name)
		if err != nil {
			return err
		}
	}
```

**File:** internal/skills/installer/installer.go (L195-225)
```go
	safeSkillDir, err := safepaths.ParseAbsolute(skillDir)
	if err != nil {
		return fmt.Errorf("could not resolve target path: %w", err)
	}

	return filepath.WalkDir(srcDir, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(srcDir, p)
		if err != nil {
			return err
		}

		// Defensive: filepath.WalkDir cannot produce traversal paths, but we
		// guard against it in case the walk input is ever changed.
		safeDest, err := safeSkillDir.Join(relPath)
		if err != nil {
			var traversalErr safepaths.PathTraversalError
			if errors.As(err, &traversalErr) {
				return fmt.Errorf("blocked path traversal in %q", relPath)
			}
			return fmt.Errorf("could not resolve destination path: %w", err)
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
