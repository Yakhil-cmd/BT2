Confirmed: this is a real gap and matches the upstream GitHub advisory pattern for `gh extension` binary installs.

### Title
Missing checksum/attestation verification when installing precompiled extension binaries - (File: pkg/cmd/extension/manager.go)

### Summary
`(Manager).Install` at [1](#0-0)  dispatches to `installBin` for binary extensions, which downloads a release asset and writes it directly to disk with no cryptographic verification of its contents. Nothing in `pkg/cmd/extension` ties the downloaded bytes to a checksum, signature, or sigstore attestation bound to the source repository, even though the codebase has a fully-featured attestation/sigstore verification stack (`pkg/cmd/attestation/verification`) that is never invoked from the extension installer.

### Finding Description
`installBin` selects a `releaseAsset` matching the current platform from the GitHub Releases API response and calls `downloadAsset` to fetch it: [2](#0-1) . `downloadAsset` in `pkg/cmd/extension/http.go` streams the HTTP response body straight to a file with mode `0755` (executable) and performs no hashing, signature check, or comparison against any manifest-declared digest: [3](#0-2) . The written `binManifest` only records `Owner`, `Name`, `Host`, `Path`, and `Tag` — no checksum or attestation reference: [4](#0-3)  and [5](#0-4) .

The repo does contain sigstore/cert-extension verification logic (`VerifyCertExtensions`, which checks `SourceRepositoryOwnerURI`, `SourceRepositoryURI`, `Issuer`, digests, and ref against an `EnforcementCriteria`) at [6](#0-5) , but this machinery is wired only into the `gh attestation verify` / `gh release verify(-asset)` commands, not into `pkg/cmd/extension`. There is no import of `pkg/cmd/attestation/verification` anywhere under `pkg/cmd/extension`.

Because a malicious/compromised extension repository owner (or anyone able to influence its release assets, e.g. via a compromised release pipeline or an intercepted/altered release upload) fully controls the asset bytes returned for `.../releases/latest` or `.../releases/tags/<tag>`, they can serve any binary matching the expected platform suffix, and `gh extension install` will execute it later with no integrity check bound to the repo identity — `codesignBinary` is only invoked conditionally for the Rosetta/arm64 fallback path and only ad-hoc codesigns, it doesn't verify provenance: [7](#0-6) .

### Impact Explanation
If a victim installs or upgrades a binary-distributed `gh` extension, the extension binary that gets written to `binPath` and later executed is trusted purely because it came from an HTTPS request to the GitHub Releases API for that repo — there is no cryptographic tie between the binary bytes and the repository/tag identity beyond TLS + GitHub's own hosting integrity. Any compromise of the release asset (supply-chain compromise, compromised maintainer account, or a malicious extension author) results in arbitrary code execution on the developer machine running `gh extension install`/`gh extension upgrade`. This matches "Remote code execution in gh" under GitHub's bug bounty scope.

### Likelihood Explanation
Preconditions are low: the attacker only needs to control (or compromise) a GitHub repository's release assets, which is exactly the threat model of an unprivileged remote attacker publishing an "extension" repo — no victim-side misconfiguration or elevated privileges are required. Any `gh extension install <owner>/<repo>` or `gh extension upgrade` against that repo triggers the vulnerable path deterministically and repeatably.

### Recommendation
Extend `installBin` (and `installGit`'s equivalent trust story) to require a verifiable binding between the downloaded asset and the source repository — e.g., verify a sigstore/GitHub attestation for the asset (reusing `pkg/cmd/attestation/verification`) with `EnforcementCriteria` pinned to the extension's `SourceRepositoryOwnerURI`/`SourceRepositoryURI`, or at minimum verify a published checksum manifest (e.g., `checksums.txt`) signed by the repo, before writing the binary to disk. Fail installation if verification is unavailable or fails, rather than silently trusting the raw release asset bytes.

### Proof of Concept
Go/httpmock-based test plan:
1. Stub `GET /repos/o/r/releases/latest` to return one asset `ext-linux-amd64` whose `APIURL` points to a mocked download endpoint.
2. Serve arbitrary attacker-chosen binary content (e.g., a shell script or ELF stub containing a marker string) from that download endpoint via `downloadAsset`'s mocked `httpClient`.
3. Call `Manager.Install(repo, "")` → `installBin`.
4. Assert that installation succeeds and `binPath` contains the attacker-controlled bytes verbatim, with no error raised and no checksum/attestation check performed — demonstrating that swapping the asset content (simulating a compromised release) is silently accepted.
5. Contrast with expected behavior: after the fix, the same test should fail install when the served bytes don't match a signed checksum/attestation for that repo+tag.

### Citations

**File:** pkg/cmd/extension/manager.go (L243-251)
```go
type binManifest struct {
	Owner    string
	Name     string
	Host     string
	Tag      string
	IsPinned bool
	// TODO I may end up not using this; just thinking ahead to local installs
	Path string
}
```

**File:** pkg/cmd/extension/manager.go (L254-280)
```go
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

**File:** pkg/cmd/extension/manager.go (L299-357)
```go
	var asset *releaseAsset
	for _, a := range r.Assets {
		if strings.HasSuffix(a.Name, platform+ext) {
			asset = &a
			trueARMBinary = isMacARM
			break
		}
	}

	// if using an ARM-based Mac and an arm64 binary is unavailable, fall back to amd64 if a relevant binary is available and Rosetta 2 is installed
	if asset == nil && isMacARM {
		for _, a := range r.Assets {
			if strings.HasSuffix(a.Name, darwinAmd64) {
				if !hasRosetta() {
					return fmt.Errorf(
						"%[1]s unsupported for %[2]s. Install Rosetta with `softwareupdate --install-rosetta` to use the available %[3]s binary, or open an issue: `gh issue create -R %[4]s/%[1]s -t'Support %[2]s'`",
						repo.RepoName(), platform, darwinAmd64, repo.RepoOwner())
				}

				fallbackMessage := fmt.Sprintf("%[1]s not available for %[2]s. Falling back to compatible %[3]s binary", repo.RepoName(), platform, darwinAmd64)
				fmt.Fprintln(m.io.Out, fallbackMessage)

				asset = &a
				break
			}
		}
	}

	if asset == nil {
		cs := m.io.ColorScheme()
		errorMessageInRed := fmt.Sprintf(cs.Red("%[1]s unsupported for %[2]s."), repo.RepoName(), platform)
		issueCreateCommand := generateMissingBinaryIssueCreateCommand(repo.RepoOwner(), repo.RepoName(), platform)

		return fmt.Errorf(
			"%[1]s\n\nTo request support for %[2]s, open an issue on the extension's repo by running the following command:\n\n	`%[3]s`",
			errorMessageInRed, platform, issueCreateCommand)
	}

	if m.dryRunMode {
		return nil
	}

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

**File:** pkg/cmd/extension/manager.go (L358-362)
```go
	if trueARMBinary {
		if err := codesignBinary(binPath); err != nil {
			return fmt.Errorf("failed to codesign downloaded binary: %w", err)
		}
	}
```

**File:** pkg/cmd/extension/manager.go (L364-371)
```go
	manifest := binManifest{
		Name:     name,
		Owner:    repo.RepoOwner(),
		Host:     repo.RepoHost(),
		Path:     binPath,
		Tag:      r.Tag,
		IsPinned: isPinned,
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

**File:** pkg/cmd/attestation/verification/extensions.go (L16-41)
```go
// VerifyCertExtensions allows us to perform case insensitive comparisons of certificate extensions
func VerifyCertExtensions(results []*AttestationProcessingResult, ec EnforcementCriteria) ([]*AttestationProcessingResult, error) {
	if len(results) == 0 {
		return nil, errors.New("no attestations processing results")
	}

	verified := make([]*AttestationProcessingResult, 0, len(results))
	var lastErr error
	for _, attestation := range results {
		if err := verifyCertExtensions(*attestation.VerificationResult.Signature.Certificate, ec.Certificate); err != nil {
			lastErr = err
			// move onto the next attestation in the for loop if verification fails
			continue
		}
		// otherwise, add the result to the results slice and increment verifyCount
		verified = append(verified, attestation)
	}

	// if we have exited the for loop without verifying any attestations,
	// return the last error found
	if len(verified) == 0 {
		return nil, lastErr
	}

	return verified, nil
}
```
