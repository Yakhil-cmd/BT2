### Title
Path Traversal via Malicious Release Asset Filename in `gh release download` - (File: pkg/cmd/release/download/download.go)

### Summary
`gh release download` builds the local destination path for a downloaded release asset by joining the user-supplied destination directory with the asset's `Name` field, which is taken verbatim from the GitHub API response for the release (attacker-controlled if the victim downloads from a repository the attacker controls or has push access to). Unlike the sibling `gh run download` artifact-download code path — which explicitly protects against this exact scenario using the `safepaths` package — the release-download code path performs no traversal sanitization on the asset name before calling `filepath.Join`.

### Finding Description
`downloadAsset` calls `dest.Copy(fileName, resp.Body)`, and `destinationWriter.makePath` computes the destination as: [1](#0-0) 

```go
func (w destinationWriter) makePath(name string) string {
	if w.file == "" {
		return filepath.Join(w.dir, name)
	}
	return w.file
}
```

`name` originates from `a.Name`, a release asset name populated directly from the GitHub API's JSON response for `release.Assets` [2](#0-1) . The only validation applied to asset names before use is a Windows reserved-filename check, which rejects device names like `CON`/`PRN` but does not reject `..` path segments [3](#0-2) . `filepath.Join(dir, "../../etc/cron.d/evil")`-style names are not rejected, and the resulting path is used directly by `Copy` to create parent directories via `os.MkdirAll` and write the file via `os.OpenFile`/`io.Copy`, with no post-join containment check [4](#0-3) .

This is the same bug class as the reported "public" npm module vulnerability: user-controlled path segments joined into a base directory without validating that the result stays within that directory, permitting writes (here) outside the intended destination.

Contrast with the codebase's own `internal/safepaths` package, purpose-built to block exactly this class of bug, and used by `gh run download`'s artifact-name and zip-extraction handling: [5](#0-4) [6](#0-5) 

The run-download package has an explicit regression test proving that a malicious artifact name (`".."`) is rejected with a path-traversal error [7](#0-6) . No equivalent protection or test exists in `pkg/cmd/release/download`.

### Impact Explanation
An attacker who controls (or compromises) a GitHub repository can publish a release with an asset whose `name` field contains path traversal sequences (e.g., `../../../../.ssh/authorized_keys` or, on Windows, a drive-relative/UNC-style path). When an unprivileged victim runs `gh release download <tag>` (or the no-argument/latest-release form) against that repository, `gh` will write the downloaded asset content to the attacker-chosen path outside the intended destination directory, subject only to the OS-level file permissions of the invoking user. This can result in arbitrary file overwrite/creation within the user's permission scope — e.g., clobbering shell startup files, SSH authorized_keys, or planting files in autorun/startup locations — a stronger impact than the original disclosure's read-only traversal.

### Likelihood Explanation
Reachability requires no special privileges beyond the normal, documented `gh release download` workflow: a remote, unprivileged attacker who controls asset naming on any repository (their own, a fork, or a compromised project) can trigger this the moment a victim downloads a release from that repository. Asset names are freely settable via the GitHub release/upload API and are not sanitized server-side for this purpose. No MITM, local access, or leaked credentials are needed — only that the victim voluntarily runs `gh release download` against the attacker's repo, which is a normal and common CLI usage pattern (e.g., following a README instruction).

### Recommendation
Sanitize/validate the asset name before joining it into the destination path, mirroring the protection already implemented in `pkg/cmd/run/download`:
- Convert the destination directory to a `safepaths.Absolute` and use `Absolute.Join(name)` (or equivalent containment check via `filepath.Rel` + `..` prefix rejection) in `destinationWriter.makePath`/`Copy`, rejecting or erroring on any traversal attempt.
- Alternatively, at minimum, restrict the asset filename to its base name (`filepath.Base(name)`) and reject names containing path separators, in addition to the existing Windows-reserved-filename check.
- Add a regression test analogous to `pkg/cmd/run/download/download_test.go`'s "handling artifact name with path traversal exploit" case for `pkg/cmd/release/download`.

### Proof of Concept
1. Attacker creates/controls a GitHub repository and publishes a release, uploading a release asset via the GitHub API/`gh release upload` equivalent with a crafted name such as `../../../../tmp/pwned` (path separator handling on the API/CDN side does not block the client-visible `name` field from containing `..` segments when returned in the release JSON).
2. Victim runs, from any working directory:
   ```
   gh release download v1.0.0 -R attacker/repo
   ```
3. `downloadRun` fetches the release, builds `toDownload` from `release.Assets` (including the crafted name) [8](#0-7) , and `downloadAsset`/`Copy` joins `opts.Destination` (default `.`) with the crafted name via `filepath.Join`, writing the asset content to a path resolved outside the current directory [9](#0-8) .
4. Result: a file is written at `/tmp/pwned` (or any path reachable via enough `../` segments and OS permissions) instead of inside the intended download directory.

Note: I was unable to fully verify the exact GitHub API/server-side constraints on what characters are permitted in a release asset's `name` field (this depends on GitHub.com/Enterprise server behavior, which is outside this repository's index). The client-side code path in `pkg/cmd/release/download/download.go`, however, performs no defense-in-depth sanitization of that field before using it in a filesystem join, which is the root cause identified here regardless of server-side constraints.

### Citations

**File:** pkg/cmd/release/download/download.go (L195-242)
```go
	} else {
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

	if len(toDownload) == 0 {
		if len(release.Assets) > 0 {
			return errors.New("no assets match the file pattern")
		}
		return errors.New("no assets to download")
	}

	if len(toDownload) > 1 && opts.OutputFile != "" {
		return fmt.Errorf("unable to write more than one asset with `--output`, got %d assets", len(toDownload))
	}

	// An asset written to standard output is external content. It funnels through
	// ContentOut so the sink is auditable; the safety decision (refuse binary bound
	// for a terminal or escape sequences in text, unless --allow-escape-sequences)
	// is made per copy below. Writing to a file keeps the raw bytes.
	opts.IO.SetContentSanitization(false)

	dest := destinationWriter{
		file:         opts.OutputFile,
		dir:          opts.Destination,
		skipExisting: opts.SkipExisting,
		overwrite:    opts.OverwriteExisting,
		stdout:       opts.IO.ContentOut,
		allowEscapes: opts.AllowEscapeSequences,
		isTTY:        opts.IO.IsStdoutTTY(),
	}

	targets := make([]downloadTarget, len(toDownload))
	for i, a := range toDownload {
		targets[i] = downloadTarget{
			url:  safeurl.NewImmutableSafeURL(a.APIURL),
			name: a.Name,
		}
```

**File:** pkg/cmd/release/download/download.go (L379-454)
```go
func (w destinationWriter) makePath(name string) string {
	if w.file == "" {
		return filepath.Join(w.dir, name)
	}
	return w.file
}

// Check returns an error if a file already exists at destination
func (w destinationWriter) Check(name string) error {
	if name == "" {
		// skip check as file name will only be known after the API request
		return nil
	}
	fp := w.makePath(name)
	if fp == "-" {
		// writing to stdout should always proceed
		return nil
	}
	return w.check(fp)
}

func (w destinationWriter) check(fp string) error {
	if _, err := os.Stat(fp); err == nil {
		if w.skipExisting {
			return errSkipped
		}
		if !w.overwrite {
			return fmt.Errorf(
				"%s already exists (use `--clobber` to overwrite file or `--skip-existing` to skip file)",
				fp,
			)
		}
	}
	return nil
}

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

**File:** internal/safepaths/absolute.go (L38-57)
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
