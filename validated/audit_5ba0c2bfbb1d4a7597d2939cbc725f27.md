### Title
Non-atomic binary extension download truncates and can permanently corrupt a previously working extension - ([File: pkg/cmd/extension/http.go])

### Summary
`gh extension upgrade`/`gh extension install` for binary extensions downloads the new release asset directly on top of the existing, already-installed executable using `O_TRUNC`, with no staging file and no rollback. If the download from the extension's release host is interrupted or fails after the file has been truncated, the previously functional extension binary is left empty/corrupt and the CLI has no way to recover it, resulting in denial of service to the user until they discover the corruption and manually reinstall. This mirrors the root cause pattern in the referenced report: an operation that discards/overwrites existing, still-needed state without accounting for the possibility that the operation does not fully succeed, leaving a legitimate later operation (running the extension) unable to proceed.

### Finding Description
`downloadAsset` opens the destination path with `O_CREATE|O_WRONLY|O_TRUNC` before any bytes of the HTTP response have been validated or fully received, then streams the response body directly into that file: [1](#0-0) 

`installBin` (used both for fresh installs and, critically, for upgrades) computes `binPath` as the path inside the *existing* extension directory and passes it straight to `downloadAsset`: [2](#0-1) 

For upgrades, `upgradeBinExtension` calls `m.installBin(repo, "")` again with the same `targetDir`/`binPath` that already contains the currently working binary: [3](#0-2) 

Because `os.OpenFile` truncates the file immediately upon open, the old, working binary is destroyed the moment the write starts — before `io.Copy` has confirmed the new binary was fully and correctly downloaded. If `httpClient.Do` or `io.Copy` fails partway (network drop, host closing the connection early, TLS reset, or a compromised/misbehaving extension release host that serves a `200` and then aborts), `downloadAsset` returns an error: [4](#0-3) 

`Install`/`upgradeExtension` then simply propagate the error and stop — the on-disk manifest is not rewritten (since `writeManifest` runs only after a successful download) but the binary the manifest points to is now truncated or contains partial garbage. Unlike the skill-update path in this same codebase, which explicitly stages the new content in a sibling temp directory and only swaps it into place atomically to guarantee "a failure at any point... leaves the existing skill completely untouched" [5](#0-4) , the extension binary upgrade path has no such staging/atomic-swap guarantee.

This is the same bug class as the external report: an irreversible destructive action (truncating/overwriting existing usable state) is performed without first guaranteeing that the replacement value will actually be available, so a legitimate downstream consumer (the user running `gh <ext>`, analogous to a user calling `claim()`) is denied service.

### Impact Explanation
A user who runs `gh extension upgrade <name>` (or reinstalls with `--force`) against an extension whose release-asset host is unreliable, rate-limits, or is controlled by a malicious/compromised third party can end up with a previously working `gh` extension permanently broken (zero-byte or truncated executable) with no automatic recovery — the extension must be manually removed and reinstalled. Because gh extensions are commonly sourced from arbitrary third-party GitHub repositories, the release host is effectively attacker-influenced content from the perspective of the CLI. This is a denial-of-service to normal `gh` command usage stemming from a data-integrity flaw in the install/upgrade codepath, not a compromise of confidentiality, so severity is Low/Medium, matching the Medium severity ultimately assigned to the analogous quest-protocol report.

### Likelihood Explanation
Likelihood is moderate: it requires either a flaky/attacker network condition during `gh extension upgrade`/`install` or a malicious/compromised extension release host that intentionally serves a truncated response after a `200 OK`. No special privileges are needed by the triggering party (the extension publisher or a network-position actor causing the interruption), and the vulnerable code path (`gh extension upgrade`) is a normal, frequently-run CLI command, unlike the original `onlyOwner`-gated function that reduced likelihood in the source report.

### Recommendation
Download the new asset to a temporary file in the same directory (or a sibling staging directory, as already done in `internal/skills/update/update.go`'s `updateSkillInPlace`), verify the write completed successfully (and optionally checksum/codesign-verify it), and only then atomically `os.Rename` it over the existing binary. This guarantees that any failure during download leaves the previously installed, working extension binary untouched.

### Proof of Concept
1. Install a binary extension: `gh extension install owner/gh-foo`.
2. Run `gh extension upgrade gh-foo` while the release asset host (`asset.APIURL`) closes the TCP connection or returns a truncated body partway through the response (this can be simulated with a test HTTP server that writes partial bytes then closes the connection, similar to the existing `httpmock` tests in `pkg/cmd/extension/manager_test.go`, e.g. `TestManager_UpgradeExtension_BinaryExtension`, but injecting a mid-stream failure instead of a clean `httpmock.StringResponse`).
3. Observe that `m.installBin` returns `"failed to download asset ...: <copy error>"` and that `filepath.Join(targetDir, name+ext)` now exists but is empty or truncated, while the on-disk `binManifest` still references the old (now-corrupted) `Path`.
4. Running `gh foo` afterward fails because the previously working executable no longer exists in a runnable state — full denial of service for that extension until manual `gh extension remove`/`install`.

### Citations

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

**File:** pkg/cmd/extension/manager.go (L341-357)
```go
	name := repo.RepoName()
	if err := m.cleanExtensionUpdateDir(name); err != nil {
		return err
	}

	targetDir := filepath.Join(m.installDir(), name)
	if err = os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create installation directory: %w", err)
	}

	binPath := filepath.Join(targetDir, name)
	binPath += ext

	err = downloadAsset(m.client, safeurl.NewImmutableSafeURL(asset.APIURL), binPath)
	if err != nil {
		return fmt.Errorf("failed to download asset %s: %w", asset.Name, err)
	}
```

**File:** pkg/cmd/extension/manager.go (L570-576)
```go
func (m *Manager) upgradeBinExtension(ext *Extension) error {
	repo, err := ghrepo.FromFullName(ext.URL())
	if err != nil {
		return fmt.Errorf("failed to parse URL %s: %w", ext.URL(), err)
	}
	return m.installBin(repo, "")
}
```

**File:** pkg/cmd/skills/update/update.go (L407-418)
```go
// updateSkillInPlace installs the resolved update into a staging directory
// alongside the existing skill directory and, on success, atomically swaps
// the staged contents into place via same-filesystem renames. This
// guarantees:
//
//   - The skill directory's own inode is preserved, so symlinks, mounts, and
//     external references that point at it stay valid.
//   - Stale files from the previous version are removed.
//   - A failure at any point (install, read, rename) leaves the existing
//     skill completely untouched: existing files are first moved aside into
//     a backup directory and restored if any subsequent step fails.
func updateSkillInPlace(opts *UpdateOptions, u pendingUpdate, apiClient *api.Client, gitRoot, homeDir string) error {
```
