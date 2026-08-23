### Title
Unsanitized release asset name allows path traversal write outside `--dir` destination - (File: pkg/cmd/release/download/download.go)

### Summary
`downloadAssets`/`downloadAsset` pass the release asset's `Name` field straight through to `destinationWriter.makePath`, which does `filepath.Join(w.dir, name)` with no traversal or absolute-path check. Unlike the archive-download branch, which sanitizes the server-derived filename with `filepath.Base` before using it, the ordinary (non-archive) asset path never sanitizes `a.Name`.

### Finding Description
In `downloadRun`, each release asset's `Name` (attacker-controlled at upload time by whoever creates the release) is copied verbatim into a `downloadTarget{name: a.Name}` [1](#0-0) . `downloadAssets` dispatches these targets to `downloadAsset`, which calls `dest.Check(fileName)` and later `dest.Copy(fileName, resp.Body)` [2](#0-1) .

`destinationWriter.makePath` builds the on-disk path with a plain `filepath.Join(w.dir, name)` [3](#0-2) , and `Copy` subsequently calls `os.MkdirAll(dir, 0755)` on `filepath.Dir(fp)` and opens the file for writing with `O_CREATE|O_TRUNC` [4](#0-3) . `filepath.Join` only performs `Clean`; it does not prevent a `name` containing `..` segments (e.g. `../../../etc/cron.d/evil` or, on a fresh checkout, `../.git/hooks/post-checkout`) from resolving outside `w.dir`. No call to `filepath.Base`, `filepath.Rel`, or any check against the joined result exists on this path.

By contrast, when downloading an archive (`--archive=zip|tar.gz`), the server-provided `Content-Disposition` filename is explicitly sanitized with `filepath.Base(serverFileName)` before being handed to `dest.Copy` [5](#0-4) . This shows the sanitization pattern exists in the codebase but is not applied to the regular per-asset `a.Name` value used by `downloadAsset`/`makePath`.

Note: `gh release download` does not extract zip/tar archives itself — the archive is written to disk as a single file — so there is no in-process zip/tar-entry extraction loop to compare against; the only "API-provided path" reaching the filesystem writer for individual files is `ReleaseAsset.Name`.

### Impact Explanation
If a crafted release asset name containing path traversal sequences (or, depending on how `os.OpenFile`/`filepath.Join` behave with a rooted component, an absolute path) reaches `makePath` unfiltered, `gh release download` can write attacker-controlled bytes to an arbitrary path relative to (or outside) the chosen `--dir`, e.g. overwriting shell profile files, `.git/hooks/*`, or other startup files reachable from the user's home/working directory — matching the "Arbitrary file write/overwrite outside intended directory, escalating to code execution" impact class.

### Likelihood Explanation
Exploitability hinges entirely on whether GitHub's Releases API accepts and returns asset `name` values containing `/` or `..` segments. That server-side behavior cannot be verified from this repository — GitHub's release-asset upload endpoint is known to reject/rewrite filenames containing path separators, which would prevent this from being reachable through the real API. Within this codebase alone, there is no client-side defense (no `filepath.Base`/`filepath.Clean` boundary check on `a.Name`), so if any code path (custom GHES instance, future API change, or a different attacker-controlled response) ever supplies a slash-containing name, the write would not be contained.

### Recommendation
Sanitize `name` in `destinationWriter.makePath` (or immediately before use in `downloadAsset`) the same way the archive branch already does: apply `filepath.Base(name)` and/or verify with `filepath.Rel(w.dir, filepath.Join(w.dir, name))` that the resulting path does not contain a leading `..` element or resolve outside `w.dir`, rejecting the download otherwise.

### Proof of Concept
```go
func TestDestinationWriter_MakePath_Traversal(t *testing.T) {
    dw := destinationWriter{dir: "/tmp/safe-dest"}
    fp := dw.makePath("../../etc/cron.d/evil")
    // Currently fp resolves outside dw.dir because makePath performs a bare filepath.Join
    // with no containment check.
    rel, err := filepath.Rel(dw.dir, fp)
    require.NoError(t, err)
    require.True(t, strings.HasPrefix(rel, ".."),
        "expected path to escape destination dir, got %q", fp)
}
```
Extend with an `httpmock` release-assets response containing `"name": "../../evil"` fed into `downloadRun`, asserting no file is created outside `opts.Destination` once a fix (e.g., `filepath.Base` or `Rel`-based containment check) is applied — the current code allows the file to be written outside `Destination`.

Caveat: whether this is reachable end-to-end depends on GitHub's server-side asset-name validation, which is outside this repository's code and was not verified here.

### Citations

**File:** pkg/cmd/release/download/download.go (L238-243)
```go
	for i, a := range toDownload {
		targets[i] = downloadTarget{
			url:  safeurl.NewImmutableSafeURL(a.APIURL),
			name: a.Name,
		}
	}
```

**File:** pkg/cmd/release/download/download.go (L300-303)
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

**File:** pkg/cmd/release/download/download.go (L431-454)
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
}
```
