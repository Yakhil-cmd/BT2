### Title
Uncontrolled Resource Consumption via Unbounded Downloads and Zip Extraction - (File: `internal/zip/zip.go`, `pkg/cmd/run/download/http.go`, `pkg/cmd/extension/http.go`, `pkg/cmd/release/download/download.go`)

### Summary
The Nextcloud report describes an endpoint that streams an attacker-controlled amount of data back to the client with no size cap or rate limiting, enabling a denial-of-service. `gh` has an analogous, reachable pattern on the *client* side: every code path that downloads server-supplied content (workflow run artifacts, release assets, `gh` extensions, Copilot CLI binaries) copies the HTTP response body — and, for zip archives, every decompressed file inside it — using unbounded `io.Copy` calls with no byte-count limit anywhere in the codebase.

### Finding Description
`downloadArtifact` in `pkg/cmd/run/download/http.go` performs: [1](#0-0) 
`io.Copy(tmpfile, resp.Body)` with no size limit, so the full HTTP response body — whatever size an artifact endpoint returns — is written to local disk unconditionally.

The resulting file is then opened as a zip and extracted via `ghzip.ExtractZip`, which for every entry calls: [2](#0-1) 
Again `io.Copy(df, f)` has no per-file or cumulative size limit, and there is no check of the compression ratio, entry count, or total uncompressed size before extraction begins.

The same unbounded pattern recurs in the other network-to-disk paths:
- `downloadAsset` for `gh extension install` — `io.Copy(f, resp.Body)`: [3](#0-2) 
- `downloadAsset` for `gh release download` — `dest.Copy(fileName, resp.Body)`, itself backed by unbounded copy: [4](#0-3) 
- `downloadCopilot` for the Copilot CLI installer — `io.Copy(tmpFile, io.TeeReader(resp.Body, hasher))`: [5](#0-4) 

A repo-wide check confirms there is no `io.LimitReader` or `http.MaxBytesReader` usage anywhere in the codebase, so none of these download/extraction code paths enforce a maximum size.

### Impact Explanation
Because none of these copies are bounded, any response body served for an artifact, release asset, extension asset, or a malicious/decompression-bomb zip archive can cause `gh` to write an attacker-chosen amount of data to the invoking user's disk (or, for zip archives, amplify a small download into a much larger extracted payload). This is reachable from ordinary commands — `gh run download`, `gh release download`, `gh extension install` — whenever the content being fetched is supplied or influenced by another party (e.g., a collaborator who can upload workflow artifacts/release assets, a malicious `gh` extension repository, or a compromised/attacker-controlled GHES host configured via `gh auth login --hostname`). The practical effect mirrors the original report's class: uncontrolled resource consumption / denial-of-service on the machine processing the request, here via disk exhaustion rather than server memory.

### Likelihood Explanation
Moderate. The attacker needs the victim to run one of the affected commands against content the attacker controls or can inject (an artifact/asset in a shared repository, a distributed `gh` extension, or a rogue/compromised GHES host). No credential theft, redirect abuse, or privilege escalation is required beyond that; the vulnerable copy/extraction logic executes unconditionally on any successful HTTP response.

### Recommendation
- Wrap all response-body reads used for downloads-to-disk in `io.LimitReader`/`http.MaxBytesReader` with a sane maximum, and fail the download rather than silently truncate or exhaust disk.
- In `internal/zip.ExtractZip`/`extractZipFile`, validate uncompressed size (per file and cumulative) and entry count against the compressed size before/while extracting, to guard against decompression bombs, similar to defenses commonly applied for zip-slip and zip-bomb mitigation.
- Apply the same caps to `pkg/cmd/extension/http.go`, `pkg/cmd/release/download/download.go`, and `pkg/cmd/copilot/copilot.go`.

### Proof of Concept
1. Set up (or compromise) a GitHub Actions workflow that uploads an artifact whose declared/reported size is large, or whose zip content decompresses to a size far larger than the transferred bytes (a classic zip bomb, e.g., many megabytes decompressing to gigabytes).
2. As a victim with access to that repository, run `gh run download <run-id>`.
3. Observe that `downloadArtifact` (`pkg/cmd/run/download/http.go`) copies the full response into a temp file without any cap, and `ExtractZip` (`internal/zip/zip.go`) extracts every entry without any cap — consuming disk space proportional to the attacker's chosen archive content, with no error or abort mechanism tied to size.

### Citations

**File:** pkg/cmd/run/download/http.go (L60-63)
```go
	size, err := io.Copy(tmpfile, resp.Body)
	if err != nil {
		return fmt.Errorf("error writing zip archive: %w", err)
	}
```

**File:** internal/zip/zip.go (L60-72)
```go
	var df *os.File
	if df, extractErr = os.OpenFile(dest.String(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, getPerm(zm)); extractErr != nil {
		return
	}

	defer func() {
		if err := df.Close(); extractErr == nil && err != nil {
			extractErr = err
		}
	}()

	_, extractErr = io.Copy(df, f)
	return
```

**File:** pkg/cmd/extension/http.go (L100-111)
```go
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
```

**File:** pkg/cmd/release/download/download.go (L326-350)
```go
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
```

**File:** pkg/cmd/copilot/copilot.go (L302-305)
```go
	hasher := sha256.New()
	if _, err := io.Copy(tmpFile, io.TeeReader(resp.Body, hasher)); err != nil {
		return "", fmt.Errorf("failed to download: %w", err)
	}
```
