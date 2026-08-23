### Title
Unsanitized release asset filename allows path traversal during `gh release download` - ([File: pkg/cmd/release/download/download.go])

### Summary
`gh release download` writes each release asset to disk using the asset's `Name` field taken directly from the GitHub API response, without sanitizing it against path traversal sequences. This is analogous to the `OracleLess` bug, where an attacker-controlled value (`tokenIn`) is trusted without restriction and later used in a sensitive operation (`safeTransfer`) that a griefer can weaponize. Here, an attacker-controlled value (the release asset's `name`, published by whoever owns/administers the target repository's release) is trusted and used directly to build a filesystem path that a victim's `gh` client writes to.

### Finding Description
In `downloadRun`/`downloadAsset` (`pkg/cmd/release/download/download.go`), each `shared.ReleaseAsset.Name` returned by the GitHub API is passed straight through to `destinationWriter.Copy`/`Check`: [1](#0-0) 

The write path is computed with a plain `filepath.Join`, with no `filepath.Base` or traversal-neutralizing check applied to the asset-derived `name`: [2](#0-1) [3](#0-2) 

Notably, the *only* place in this file that sanitizes a filename with `filepath.Base` is the fallback path that derives a filename from the HTTP `Content-Disposition` header when downloading an "archive" (`--archive zip|tar.gz`): [4](#0-3) 

That protection does not apply to the normal per-asset download path, where `fileName` is always non-empty (`a.Name`) and skips this branch entirely. If a release asset's `name` contains path traversal sequences (e.g. `../../.bashrc` or a path with slashes), `filepath.Join(w.dir, name)` will resolve outside the intended `--dir`/`-D` destination, and `os.OpenFile(fp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)` will create/overwrite that file.

### Impact Explanation
A repository owner (or anyone able to publish a release with attacker-chosen asset names — attacker-published content, no special privilege over the victim required) can craft a release whose asset name is a traversal path. A victim who runs `gh release download` against that repository will have `gh` write/overwrite an arbitrary file relative to their current working directory or destination directory, e.g. shell rc files, cron files, or other files reachable with traversal, subject to OS filename restrictions. This is a concrete file write outside the intended download directory, matching the "no impact" exclusion bar set by the validation rules (this is impactful, not benign).

### Likelihood Explanation
Likelihood is meaningful but bounded by whether GitHub's release-asset upload API itself restricts path separators/traversal characters in asset filenames server-side; if GitHub's upload endpoint rejects `/`/`..` in names, this client-side gap is not independently exploitable via the API. However, the client-side code contains no defense-in-depth check, so any bypass of upstream name validation (e.g. via GitHub Enterprise Server, a different upload path, or future API relaxation) becomes a full path-traversal write with no corresponding client-side mitigation. This mirrors the sherlock report's theme: absence of an allowlist/sanitization on attacker-influenced input that the tool later uses in a filesystem/transfer operation.

### Recommendation
Sanitize `a.Name` (and any other server-provided filename) with `filepath.Base` (or explicit rejection of path separators/`..` components) before passing it into `destinationWriter.Check`/`Copy`, consistent with the existing `filepath.Base` treatment already applied to the `Content-Disposition`-derived archive filename at `pkg/cmd/release/download/download.go:344`. Additionally, verify the resolved path stays within `w.dir` via `filepath.Rel`/prefix check before opening the file for writing.

### Proof of Concept
1. Attacker creates (or compromises) a public GitHub repository and creates a release.
2. Attacker uploads a release asset whose `name` metadata is set to a path-traversal string, e.g. `..%2F..%2F..%2F.bashrc` — feasible if the GitHub asset-name validation does not block this on some API path (e.g. via a GitHub Enterprise Server instance without the same validation, or via a name that passes GitHub's checks but decodes/resolves unexpectedly).
3. Victim runs `gh release download <tag> -R attacker/repo -D ./downloads`.
4. `downloadAsset` calls `dest.Copy(fileName, resp.Body)` with `fileName` = the malicious asset name; `makePath` computes `filepath.Join("./downloads", "../../../.bashrc")`, which resolves outside `./downloads`, and `os.OpenFile` truncates/writes to that external path — corresponding to `pkg/cmd/release/download/download.go:379-384` and `pkg/cmd/release/download/download.go:441-444`.

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
