### Title
Path traversal in `gh release download` via unsanitized release asset filenames - (File: pkg/cmd/release/download/download.go)

### Summary
`gh release download` writes release assets to disk using the asset `Name` field returned by the GitHub API for the target repository's release, without sanitizing it for path traversal sequences. A malicious or compromised repository (attacker-published content, reachable simply by a victim running `gh release download owner/repo`) can name an asset with `../` segments, causing the CLI to write the downloaded file outside the intended destination directory.

### Finding Description
`downloadRun` builds `downloadTarget` entries directly from `shared.ReleaseAsset.Name` values returned by the GitHub API for the assets attached to a release: [1](#0-0) 

These names are passed unmodified into `destinationWriter.Check` and `destinationWriter.Copy`, both of which build the final filesystem path via `makePath`: [2](#0-1) 

`makePath` performs a bare `filepath.Join(w.dir, name)` with no call to `filepath.Base` or any traversal check. `Copy` then creates any missing parent directories and opens the file for writing: [3](#0-2) 

By contrast, the code path that determines an *archive* filename from the HTTP `Content-Disposition` header explicitly strips directory components with `filepath.Base(serverFileName)` before use: [4](#0-3) 

This shows the developers were aware that server/attacker-supplied filenames need sanitizing in this exact code region, but the sanitization was not applied to the (more commonly used) per-asset `Name` field taken from the release metadata, which is fully controlled by whoever created the release in the target repository — an unprivileged, remote actor from the CLI user's perspective (any repo owner/maintainer who can publish releases, or an attacker who compromises such an account).

### Impact Explanation
A crafted release asset name containing `../../` sequences lets the attacker cause `gh release download` to write arbitrary file content to any path the invoking user's OS account has write access to (e.g., overwriting `~/.bashrc`, `~/.ssh/authorized_keys`, or files under the destination directory's parent tree), because `os.MkdirAll` will even create the necessary intermediate directories. This is a concrete "file write outside the intended path" primitive, potentially leading to code execution if the overwritten file is later sourced/executed (shell rc files, cron files, etc.).

### Likelihood Explanation
Likelihood is moderate: it requires the victim to run `gh release download` against a repository controlled by (or whose release-publishing permission is held by) the attacker. This is a normal, common `gh` workflow (downloading release assets from third-party or internal repos), so the reachable surface is realistic, though it depends on whether GitHub's release-asset-upload API itself permits slash/traversal characters in asset names (unverified from this codebase alone, since asset creation happens server-side, not in this repo). If GitHub's backend does not restrict asset names, this is directly exploitable by any external contributor publishing a release; if it restricts them, exploitability shifts to GitHub Enterprise Server instances or API quirks that may allow such names.

### Recommendation
Sanitize asset names before using them as filesystem paths in `destinationWriter.makePath` — apply `filepath.Base(name)` (as already done for the archive `Content-Disposition` case) and/or explicitly reject names containing path separators or `..` segments, consistently for both the per-asset and archive download paths.

### Proof of Concept
1. Attacker creates/controls a public GitHub repository and publishes a release with an asset whose `Name` is set to `../../../../tmp/evil` (or similar traversal payload), via GitHub's release asset upload API.
2. Victim runs `gh release download v1.0.0 --repo attacker/repo` (or without `-p`/`-A`, matching all assets).
3. `downloadRun` enumerates `release.Assets`, uses the malicious `Name` unmodified as `downloadTarget.name`.
4. `downloadAsset` → `dest.Copy(fileName, resp.Body)` → `makePath` joins `w.dir` with the traversal-laden name, resulting in a file written outside `--dir`/current working directory, e.g., under `/tmp` instead of the intended download directory. [5](#0-4) [6](#0-5)

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

**File:** pkg/cmd/release/download/download.go (L300-304)
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
