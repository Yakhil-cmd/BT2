Found a clear path-traversal analog. In `pkg/cmd/release/download/download.go`, asset filenames are joined into the destination directory with plain `filepath.Join`, with no traversal guard — unlike sibling download commands (`run/download`, `internal/zip`, `pkg/cmd/copilot`) that all route through the `internal/safepaths.Absolute.Join()` helper specifically built to reject `..` traversal.

### Title
Path Traversal in `gh release download` via unsanitized release asset name - (File: `pkg/cmd/release/download/download.go`)

### Summary
`gh release download` writes each release asset to `<destination-dir>/<asset.Name>` using an unguarded `filepath.Join`. The `asset.Name` value originates from the GitHub API's JSON response for the release (`shared.ReleaseAsset.Name`), which is attacker-influenced content (e.g., anything a repository collaborator names a release asset, or any value an attacker-controlled/compromised GitHub Enterprise Server host returns for that JSON field). If the name contains `../` sequences, the resulting path escapes the user-specified `--dir`, mirroring the CVE-2023-30584 class of bug: a directory-restriction check is bypassed by `..` path traversal during a normal, expected command invocation.

### Finding Description
The download flow is:
1. `downloadRun` builds `targets` directly from `release.Assets`, using `a.Name` verbatim as the file name: [1](#0-0) 
2. `downloadAsset` passes that name straight to `dest.Copy(fileName, resp.Body)` with no sanitization beyond an OS-reserved-filename check that does not address traversal: [2](#0-1) 
3. `destinationWriter.makePath` computes the on-disk path with a bare `filepath.Join(w.dir, name)`, which does **not** prevent `..` from escaping `w.dir`: [3](#0-2) 
4. `Copy` then creates parent directories and writes the file at that unguarded path: [4](#0-3) 

This is the exact bug class from the report: a filesystem "write inside this directory" boundary (`--dir`) that is defeated by a `..`-containing name, because the join operation is not checked against a subpath invariant.

By contrast, the same codebase already has a dedicated fix for this class of bug, `internal/safepaths.Absolute.Join`, which computes the joined absolute path and explicitly rejects it via `PathTraversalError` if it is not a subpath of the base: [5](#0-4) . That helper is used to defend `gh run download` (artifact ZIP extraction and per-artifact isolation directories): [6](#0-5) , `internal/zip.ExtractZip`: [7](#0-6) , and Copilot CLI archive extraction: [8](#0-7) . `pkg/cmd/release/download/download.go`'s `destinationWriter` was never updated to use this shared protection.

### Impact Explanation
An attacker who can create or edit release assets on any repository (including their own public repo) can name an asset something like `..%2F..%2F.bashrc` or, since GitHub asset names typically block `/`, an attacker who instead controls the API host (a malicious/compromised GitHub Enterprise Server, matching the "attacker-controlled host during a normal gh command" validation rule) can return a crafted `name` field containing `../` sequences in the release/asset JSON. When a victim runs `gh release download` (or `gh release download -p <pattern>`) against that host/repo, the file is written outside the intended `--dir`, silently overwriting or planting arbitrary files at attacker-chosen relative paths (e.g., overwriting shell rc files, SSH config, or dropping executables into locations the victim will later execute). This is a concrete file-write-outside-intended-path primitive reachable via a normal `gh` invocation with no local access or MITM required.

### Likelihood Explanation
Reaching this path requires only that the victim run `gh release download` against a repository/host whose release asset metadata is attacker-influenced — a routine and expected `gh` workflow (downloading release artifacts is a core use case, frequently scripted/automated). No special privileges, prompts, or unusual flags are needed; the vulnerable join happens unconditionally for every asset name.

### Recommendation
Route `destinationWriter.makePath`/`Copy` (and the `Check` variant) through `internal/safepaths.Absolute`, exactly as `pkg/cmd/run/download` and `internal/zip` already do: parse `w.dir` into a `safepaths.Absolute`, then use `.Join(name)` to compute the destination, propagating/erroring on `safepaths.PathTraversalError` instead of relying on plain `filepath.Join`. Apply `filepath.Base()` or full traversal-safe joining consistently to all asset-derived names, not just the Content-Disposition-derived archive name.

### Proof of Concept
```go
// Illustrative reproduction using the existing exported types.
dest := destinationWriter{dir: "/home/user/downloads"}
// Suppose the release JSON returns an asset with Name: "../../.ssh/authorized_keys"
fp := dest.makePath("../../.ssh/authorized_keys")
// fp == "/home/user/.ssh/authorized_keys" -- escapes /home/user/downloads
```
Compare to `gh run download`, where the analogous join is protected: [9](#0-8)  — a test explicitly asserting that a traversal-y artifact name (`".."`) is rejected with "would result in path traversal". No equivalent test or guard exists for `pkg/cmd/release/download`.

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

**File:** pkg/cmd/release/download/download.go (L416-453)
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
```

**File:** internal/safepaths/absolute.go (L38-65)
```go
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

func (a Absolute) isSubpathOf(dir Absolute) (bool, error) {
	relativePath, err := filepath.Rel(dir.path, a.path)
	if err != nil {
		return false, err
	}
	return !strings.HasPrefix(relativePath, ".."), nil
}
```

**File:** pkg/cmd/run/download/download.go (L179-188)
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
