### Title
Path traversal in `gh release download` via unsanitized release asset filenames - (File: `pkg/cmd/release/download/download.go`)

### Summary
`gh release download` builds the local destination path for a downloaded release asset directly from the asset's `name` field returned by the GitHub API, without any sanitization against path traversal sequences (e.g. `../`). Unlike the OCI/archive download branch, which strips path components from the filename with `filepath.Base(serverFileName)`, the per-asset download loop does not perform this validation, allowing a release asset name to escape the intended download directory (a Zip-Slip-style bug), analogous to the Badger `Zap.redeem()` issue of trusting an unvalidated user/attacker-supplied identifier to decide "where the output goes."

### Finding Description
When downloading regular (non-archive) release assets, `downloadRun` iterates `release.Assets` and only filters by glob pattern and Windows-reserved-name checks, but does not sanitize the asset `Name` value: [1](#0-0) 

Each matched asset is turned into a `downloadTarget{url, name: a.Name}` and passed straight through to `downloadAsset`, then to `dest.Copy(fileName, resp.Body)`: [2](#0-1) [3](#0-2) [4](#0-3) 

The destination path is computed by `destinationWriter.makePath`, which does a plain `filepath.Join(w.dir, name)` with no check that the resulting path stays within `w.dir`: [5](#0-4) 

Because `filepath.Join` calls `filepath.Clean`, a `name` value such as `"../../.ssh/authorized_keys"` collapses the `..` segments and can resolve to a path outside the intended destination directory when `-D/--dir` is a relative or shallow directory. Contrast this with the archive-download path, which explicitly calls `filepath.Base(serverFileName)` on the filename derived from `Content-Disposition` before use — indicating the codebase is aware that filenames need sanitization, but this sanitization is missing for the asset-name code path: [6](#0-5) 

Release asset names are attacker-controlled content: any GitHub user can create a public repository, publish a release, and name an uploaded asset arbitrarily (including embedded `../` sequences), because the GitHub API generally does not restrict the `name` field of a release asset to a bare filename. When a victim later runs `gh release download` (or `-p` pattern matching) against that attacker-owned or attacker-compromised repository, the CLI will write the file to the path implied by the malicious name.

### Impact Explanation
An attacker who controls (or compromises) any public/private repository that a victim is instructed to (or automated to) run `gh release download` against can cause the CLI to write a file to a location of the attacker's choosing relative to the victim's chosen destination directory (or CWD, since `--dir` defaults to `.`). This is a file-write-outside-intended-path primitive — capable of overwriting configuration files, shell profiles, cron files, or CI artifacts depending on write permissions of the invoking user, which can lead to further code execution.

### Likelihood Explanation
This requires a victim to run `gh release download` (with or without `--pattern`) against a release published by the attacker. This is a normal, expected `gh` workflow (e.g., downloading build artifacts from a third-party or forked repository, or CI pipelines that download release assets by tag/pattern from configurable repos), making it a plausible, reachable path for an unprivileged remote attacker who merely publishes content (a release asset name) that ends up being consumed by `gh` without human review of the exact filename.

### Recommendation
Sanitize asset filenames before constructing the destination path, mirroring the existing `filepath.Base()` treatment used for archive downloads:
- In the asset loop (`download.go:195-207`) and/or in `destinationWriter.makePath`/`Check`/`Copy`, reject or `filepath.Base()`-normalize `a.Name` before use.
- After computing the final path, verify (e.g., via `filepath.Rel` + reject leading `..`) that it remains within `w.dir` before opening/writing the file, and fail the download for that asset otherwise.

### Proof of Concept
1. Attacker creates a public repo, creates a release, and uploads an asset with `name` set to a traversal string, e.g. `"../../../../tmp/pwned"` (achievable via the GitHub API's release-asset upload, which allows arbitrary `name` values independent of the uploaded file's actual name).
2. Victim runs `gh release download <tag> -R attacker/repo` (or without a pattern restriction) in some working directory.
3. `downloadRun` accepts the asset (no filename sanitization) → `downloadAsset` → `dest.Copy(fileName, ...)` → `makePath` performs `filepath.Join(".", "../../../../tmp/pwned")`, which `filepath.Clean`s to a path outside the intended download directory, writing attacker-controlled content to `/tmp/pwned` (or another out-of-bounds location depending on nesting depth and destination directory).

### Citations

**File:** pkg/cmd/release/download/download.go (L195-207)
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

**File:** pkg/cmd/release/download/download.go (L300-351)
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
