### Title
Missing integrity verification for downloaded binary extension assets allows execution of tampered content - (File: `pkg/cmd/extension/manager.go`)

### Summary
`gh extension install` for binary extensions downloads a release asset by URL and writes it directly to disk as an executable, without validating its contents against any checksum, digest, or attestation captured at "check" time. This mirrors the report's root cause — a value/state is fetched and relied upon, but the actual data used for the sensitive operation is fetched later with no verification that it matches what was expected — creating a window where the artifact delivered can differ from what the user/manager believed it installed.

### Finding Description
`Manager.Install` first calls `isBinExtension`/`fetchLatestRelease`/`fetchReleaseFromTag` to resolve release metadata (asset name/URL) for the target repo, then hands off to `installBin`, which selects an asset and calls `downloadAsset` to fetch and persist it to `binPath` on disk with executable permissions: [1](#0-0) [2](#0-1) 

`downloadAsset` performs a plain HTTP GET against the asset's API URL and writes the response body straight to `destPath` (mode `0755`), with no digest computation or comparison step: [3](#0-2) 

This is notably inconsistent with another downloader in the same codebase, `downloadCopilot`, which fetches a `SHA256SUMS.txt` file up front and explicitly re-validates the downloaded archive's SHA-256 against it before extracting: [4](#0-3) 

For binary extensions, no equivalent "expected value" (checksum/digest/signature) is captured at check time and re-verified against the bytes actually persisted at use time. Just as the Market bug allowed the price used at execution to silently diverge from the price a user believed they'd get, here the binary content used at execution (as `gh <extension>`) can silently diverge from whatever the metadata request observed, with nothing enforcing consistency between the two.

### Impact Explanation
Extension binaries are later invoked directly as subprocess commands whenever the user runs `gh <extension-name>`. If the bytes written to `binPath` are not what was intended (e.g., a compromised/rotated release asset, a CDN or reverse-proxy serving different content for the same URL, or any other substitution between metadata resolution and asset retrieval), the CLI will execute that content with the user's privileges — full local code execution. This is a supply-chain integrity gap similar in nature (asymmetric trust between "checked" state and "used" state) to the missing bound/verification called out in the source report, just realized as extension installation rather than DeFi pricing.

### Likelihood Explanation
The vulnerable code path is reached by any unprivileged use of `gh extension install <owner>/<repo>` targeting a binary-release extension, which is an ordinary and common CLI operation, including installing third-party/community extensions. No special privileges are required to trigger the download-and-execute flow; the only requirement is that the attacker (or a compromised intermediary/host serving the asset URL) can influence the bytes returned for the asset URL.

### Recommendation
Require and verify an integrity value for binary extension assets before writing them to disk/marking them executable, consistent with the pattern already implemented for the Copilot CLI downloader (`fetchExpectedChecksum` + SHA-256 comparison in `downloadCopilot`). Where available, prefer verifying against the GitHub Releases API asset `digest` field (already present on `ReleaseAsset.Digest` in `pkg/cmd/release/shared/fetch.go`) or a `gh attestation verify`-style attestation check, and fail closed if no verifiable digest can be obtained.

### Proof of Concept
1. Publish (or compromise/serve via a MITM-capable intermediary) a binary release asset at the URL that `fetchLatestRelease`/`fetchReleaseFromTag` reports for a given platform suffix.
2. Run `gh extension install <owner>/<repo>` (or `gh extension upgrade`, which follows the same `installBin` path via `pkg/cmd/extension/manager.go:520-545`).
3. Observe that `downloadAsset` writes the response body directly to `binPath` with no digest/checksum comparison, and the resulting binary is subsequently executed via `gh <extension-name>` — contrast with `downloadCopilot`, which would reject a tampered archive due to its SHA-256 check. [5](#0-4)

### Citations

**File:** pkg/cmd/extension/manager.go (L253-280)
```go
// Install installs an extension from repo, and pins to commitish if provided
func (m *Manager) Install(repo ghrepo.Interface, target string) error {
	isBin, err := isBinExtension(m.client, repo)
	if err != nil {
		if errors.Is(err, releaseNotFoundErr) {
			if ok, err := repoExists(m.client, repo); err != nil {
				return err
			} else if !ok {
				return repositoryNotFoundErr
			}
		} else {
			return fmt.Errorf("could not check for binary extension: %w", err)
		}
	}
	if isBin {
		return m.installBin(repo, target)
	}

	hs, err := hasScript(m.client, repo)
	if err != nil {
		return err
	}
	if !hs {
		return fmt.Errorf("extension is not installable: no usable release artifact or script found in %s", ghrepo.FullName(repo))
	}

	return m.installGit(repo, target)
}
```

**File:** pkg/cmd/extension/manager.go (L282-294)
```go
func (m *Manager) installBin(repo ghrepo.Interface, target string) error {
	var r *release
	var err error
	isPinned := target != ""
	if isPinned {
		r, err = fetchReleaseFromTag(m.client, repo, target)
	} else {
		r, err = fetchLatestRelease(m.client, repo)
	}
	if err != nil {
		return err
	}

```

**File:** pkg/cmd/extension/manager.go (L351-357)
```go
	binPath := filepath.Join(targetDir, name)
	binPath += ext

	err = downloadAsset(m.client, safeurl.NewImmutableSafeURL(asset.APIURL), binPath)
	if err != nil {
		return fmt.Errorf("failed to download asset %s: %w", asset.Name, err)
	}
```

**File:** pkg/cmd/extension/http.go (L78-112)
```go
// downloadAsset downloads a single asset to the given file path.
func downloadAsset(httpClient *http.Client, assetURL safeurl.SafeURL, destPath string) (downloadErr error) {
	var req *http.Request
	if req, downloadErr = http.NewRequest("GET", assetURL.String(), nil); downloadErr != nil {
		return
	}

	req.Header.Set("Accept", "application/octet-stream")

	var resp *http.Response
	// TODO(api-client-rollout)
	// This has been deferred from moving to api.Client due to its custom Accept header and binary response streaming.
	if resp, downloadErr = httpClient.Do(req); downloadErr != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		downloadErr = api.HandleHTTPError(resp)
		return
	}

	var f *os.File
	if f, downloadErr = os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755); downloadErr != nil {
		return
	}
	defer func() {
		if err := f.Close(); downloadErr == nil && err != nil {
			downloadErr = err
		}
	}()

	_, downloadErr = io.Copy(f, resp.Body)
	return
}
```

**File:** pkg/cmd/copilot/copilot.go (L276-313)
```go
	expectedChecksum, err := fetchExpectedChecksum(httpClient, checksumsURL, archiveName)
	if err != nil {
		return "", fmt.Errorf("failed to fetch checksums: %w", err)
	}

	ios.StartProgressIndicatorWithLabel(fmt.Sprintf("Downloading Copilot CLI from %s", archiveURL.String()))
	defer ios.StopProgressIndicator()

	resp, err := httpClient.Get(archiveURL.String())
	if err != nil {
		return "", fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status: %s", resp.Status)
	}

	// Download to temp file while calculating checksum
	tmpFile, err := os.CreateTemp("", "copilot-download-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	hasher := sha256.New()
	if _, err := io.Copy(tmpFile, io.TeeReader(resp.Body, hasher)); err != nil {
		return "", fmt.Errorf("failed to download: %w", err)
	}

	ios.StopProgressIndicator()

	// Validate checksum
	actualChecksumHex := hex.EncodeToString(hasher.Sum(nil))
	if actualChecksumHex != expectedChecksum {
		return "", fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksumHex)
	}
```
