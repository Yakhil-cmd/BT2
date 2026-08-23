## Title
Path traversal in `gh release download` via unsanitized release asset filenames - (File: pkg/cmd/release/download/download.go)

### Summary
`gh release download` writes downloaded release assets to disk using the asset's `name` field taken directly from the GitHub Releases API, joined with the destination directory via `filepath.Join`, without stripping `../` path segments. A remote, unprivileged attacker who controls a repository (or a release within it) that the victim chooses to run `gh release download` against can name an asset with path-traversal sequences and cause the CLI to write the downloaded file outside the intended destination directory.

### Finding Description
This is analyzed as an unprivileged remote-attacker "check happens on the wrong value" bug in the same family as the reported reentrancy issue: a safety check (`Check`/`check`, which blocks overwriting existing files) is performed against a path derived from an attacker-controlled value, but the code never neutralizes traversal sequences within that value before using it to construct the filesystem path.

In `downloadRun`, assets to download come straight from `release.Assets` (`pkg/cmd/release/download/download.go:196-207`), and each asset's `Name` field is used unmodified as the `downloadTarget.name`: [1](#0-0) 

That name flows into `downloadAsset`, which calls `dest.Check(fileName)` and later `dest.Copy(fileName, resp.Body)`: [2](#0-1) 

Both `Check`/`check` and `Copy` compute the destination path via `makePath`, which does a raw `filepath.Join(w.dir, name)` with no cleaning of `..` segments and no confinement check against `w.dir`: [3](#0-2) [4](#0-3) [5](#0-4) 

`filepath.Join` normalizes `..` segments arithmetically rather than rejecting them, so a name such as `../../.ssh/authorized_keys` (or a deeper traversal) resolves to a path outside `w.dir`. The existing "already exists" check (`w.check`) only prevents overwriting *known* files at that resolved path and does nothing to constrain the path to the destination directory — it's the wrong check for the wrong risk. The only filename hardening present is `isWindowsReservedFilename`, which validates against reserved Windows device names, not path traversal: [6](#0-5) 

By contrast, the code path that derives filenames from an HTTP response's `Content-Disposition` header (used for unnamed/archive downloads) does apply `filepath.Base()` to strip any directory components: [7](#0-6) 
This inconsistency shows the intended invariant ("asset filenames must not escape the destination directory") is enforced in one code path but not the other — an asset that has a normal `Name` on the Releases API is trusted verbatim.

Note that this is distinct from `gh run download`, `gh repo read-file`, and the skills installer paths inspected in the same repo, all of which use `internal/safepaths` (`safepaths.Absolute.Join`) to explicitly detect and reject traversal: [8](#0-7) [9](#0-8) 
`pkg/cmd/release/download` does not use `safepaths` at all for asset names.

### Impact Explanation
If an attacker can get a victim to run `gh release download` against a repository/release they control (e.g., a public repo the victim was told to download from, or a release the victim was pointed to), the attacker can name a release asset with `..`-laden path segments. When the CLI downloads it, the resulting file is written to a path outside the user-specified `--dir`/`-D` destination, potentially overwriting files elsewhere on the victim's filesystem that the invoking user has write access to (e.g., shell rc files, SSH `authorized_keys`, cron files, or other application configs), leading to file write outside the intended path and potential follow-on code execution depending on which file is clobbered.

### Likelihood Explanation
GitHub's release upload UI/API places some restrictions on asset names, but the strength of that server-side validation is not verified in-repo and cannot be assumed absolute; the client-side code performs zero defense-in-depth here despite doing so for the Content-Disposition-derived path. Given that this only requires an attacker to control a repository/release (no privileged relationship to the victim's `gh` installation, no MITM, no local access), and the victim need only run a standard `gh release download` command, likelihood is realistic though it does depend on whatever filename constraints GitHub's API currently enforces server-side.

### Recommendation
Sanitize/validate every asset `name` before using it in `filepath.Join`: reject or strip path separators and `..` segments (e.g., `filepath.Base(name)`), or route all destination path construction through the same `safepaths.Absolute.Join`-style confinement check already used in `pkg/cmd/run/download` and the skills installer, returning an explicit "would result in path traversal" error instead of silently normalizing the path.

### Proof of Concept
1. Attacker creates/controls a repository and publishes a release with an asset whose `name` is set to a value such as `../../../../tmp/pwned` (via the GitHub API's release asset upload, bypassing any client-side-only restriction if the server does not fully validate the name).
2. Victim runs `gh release download <tag> --repo attacker/repo -D ./safe-dir`.
3. `downloadRun` enumerates `release.Assets` and passes the asset's `Name` unchanged into `downloadTarget.name`, per `pkg/cmd/release/download/download.go:237-243`.
4. `downloadAsset` calls `dest.Check(fileName)` and then `dest.Copy(fileName, resp.Body)`; both resolve the destination via `filepath.Join(w.dir, name)` in `makePath` (`pkg/cmd/release/download/download.go:379-384`), which follows the `../` segments outside `./safe-dir`.
5. The downloaded asset content is written to the traversal-resolved path instead of remaining confined to `./safe-dir`.

I was not able to fully verify server-side filename validation on GitHub's Releases API from this codebase alone (that enforcement lives outside this repo), so the exact set of achievable traversal payloads depends on GitHub API behavior not visible in this index; the client-side code, however, provides no independent protection against it.

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

**File:** pkg/cmd/release/download/download.go (L300-348)
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

**File:** pkg/cmd/release/download/download.go (L400-413)
```go
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
```

**File:** pkg/cmd/release/download/download.go (L431-453)
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
	return
```

**File:** pkg/cmd/release/download/download.go (L456-460)
```go
func isWindowsReservedFilename(filename string) bool {
	// Windows terminals should prevent the creation of these files
	// but that behavior is not enforced across terminals. Prevent
	// the user from downloading files with these reserved names as
	// they represent an exploit vector for bad actors.
```

**File:** internal/skills/installer/installer.go (L280-288)
```go
		safeDest, err := safeSkillDir.Join(relPath)
		if err != nil {
			var traversalErr safepaths.PathTraversalError
			if errors.As(err, &traversalErr) {
				return fmt.Errorf("blocked path traversal in %q", relPath)
			}
			return fmt.Errorf("could not resolve destination path: %w", err)
		}
		destPath := safeDest.String()
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
