### Title
Path Traversal via Unsanitized Release Asset Filename in `gh release download` - (File: pkg/cmd/release/download/download.go)

### Summary
`gh release download` writes each release asset to disk using the asset's `name` field taken directly from the GitHub API release response, without sanitizing it against path traversal sequences before joining it to the destination directory. A malicious or compromised repository (or GitHub-API-compatible/GHES host) can publish a release asset whose `name` contains `../` sequences, causing the CLI to write the downloaded content outside the user-specified `--dir` destination when the victim runs a normal `gh release download` command against that repository.

### Finding Description
In `downloadRun`, the asset name (`a.Name`) is taken verbatim from the parsed release JSON and passed through unmodified as the `downloadTarget.name` field [1](#0-0) [2](#0-1) . That name is only checked against Windows reserved filenames, never against path-separator or `..` traversal sequences [3](#0-2) .

The name flows into `destinationWriter.makePath`, which builds the on-disk path with a plain `filepath.Join(w.dir, name)` [4](#0-3) . `filepath.Join` calls `filepath.Clean`, which resolves `..` segments rather than rejecting them, so a name such as `../../../../tmp/evil` collapses the joined path outside the intended `--dir` destination. The subsequent `Copy` routine creates any missing parent directories with `os.MkdirAll` and then opens the file for writing with `O_CREATE|O_TRUNC`, with no post-Join containment check that the resulting path is still inside `w.dir` [5](#0-4) .

For the archive-download path (`--archive zip|tar.gz`), the filename instead comes from the server's `Content-Disposition` header and is passed through `filepath.Base`, which does neutralize traversal there [6](#0-5) . However, the per-asset path (the default, non-archive case) has no equivalent sanitization for `a.Name`.

### Impact Explanation
This is a file-write-outside-intended-path primitive triggered purely by running a documented, unprivileged command (`gh release download`) against a repository/host that supplies a crafted release asset name. Depending on where `gh` is invoked from and attacker-chosen traversal depth, this could overwrite arbitrary files reachable by the invoking user (e.g., shell profile files, cron files, or other files under the user's write permissions), potentially leading to code execution on next shell/login. No user interaction beyond running the normal download command is required, and no additional privilege is needed by the attacker beyond controlling (or spoofing, via a malicious/GHES-style API host) the release metadata.

### Likelihood Explanation
Exploitability depends on whether the asset `name` field can actually contain `/` or `..` sequences when returned by a given host's Releases API. GitHub.com's own asset upload path may restrict this, but the CLI must also support GitHub Enterprise Server and any host implementing the same REST API contract, and the client performs no independent validation. Since the check exists only for Windows reserved names and not for path traversal, the client trusts the API response's `name` field unconditionally, making this a real, reachable gap in the code path rather than a purely theoretical one.

### Recommendation
Sanitize `a.Name` (and any other server-provided filename) before use, e.g., apply `filepath.Base` (as already done for the Content-Disposition-derived archive filename) and/or explicitly verify the resolved path stays within `w.dir` after `filepath.Join`, rejecting or erroring out on any asset name containing path separators or resolving outside the destination directory.

### Proof of Concept
1. Set up (or compromise) a repository whose latest release contains an asset entry with `"name": "../../../../tmp/evil-file"` and an assets `url` pointing to attacker-controlled content.
2. Victim runs `gh release download --pattern '*' -D tmp/assets` (or without a pattern, matching all assets) against that repository.
3. `downloadRun` selects this asset and calls `downloadAsset` → `dest.Copy` with `name = "../../../../tmp/evil-file"`.
4. `makePath` computes `filepath.Join("tmp/assets", "../../../../tmp/evil-file")`, which `Clean`s to a path outside `tmp/assets` (e.g., `/tmp/evil-file` relative to the working directory tree), and the file is written there via `os.OpenFile` with `O_CREATE|O_TRUNC`, confirming a write outside the intended destination directory.

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

**File:** pkg/cmd/release/download/download.go (L379-384)
```go
func (w destinationWriter) makePath(name string) string {
	if w.file == "" {
		return filepath.Join(w.dir, name)
	}
	return w.file
}
```

**File:** pkg/cmd/release/download/download.go (L415-453)
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
```
