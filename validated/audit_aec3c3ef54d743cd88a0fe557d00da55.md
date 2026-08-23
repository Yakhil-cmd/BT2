### Title
Concurrent asset downloads with filesystem-colliding names (case-insensitive/Unicode-normalized) race past the no-clobber check and silently overwrite each other - ([File: pkg/cmd/release/download/download.go])

### Summary
`downloadAssets` runs up to 5 concurrent goroutines that each independently call `dest.Check` and then `dest.Copy` for their own asset name, with no cross-goroutine locking on the resolved destination path. A release maintainer (the "attacker" in this GitHub-release threat model) can publish two assets whose `Name` fields are distinct byte strings accepted by GitHub (e.g. differing only in case, or Unicode NFC vs NFD) but which resolve to the identical path on a case-insensitive or normalization-folding filesystem (macOS APFS, Windows NTFS). Both downloads can pass their existence checks before either has written the file, then race to `os.OpenFile(..., O_TRUNC)` on the same path, producing silent data corruption/overwrite with no conflict ever reported and without `--clobber` being invoked.

### Finding Description
In `downloadAssets`, N=`opts.Concurrency` (fixed to 5) worker goroutines pull `downloadTarget`s from a shared channel and call `downloadAsset` independently: [1](#0-0) 

Each `downloadAsset` call performs a "check" then a network fetch then a "copy": [2](#0-1) [3](#0-2) 

`destinationWriter.Check`/`.check` only inspects `os.Stat` at the moment it's called — it has no notion of "another goroutine is currently downloading to this same resolved path": [4](#0-3) 

`Copy` re-checks existence immediately before `os.OpenFile` with `O_TRUNC`, but this second check is *also* per-goroutine and unsynchronized with any sibling goroutine writing to the same path: [5](#0-4) 

`makePath` derives the destination purely from `filepath.Join(w.dir, name)` with no canonicalization or dedup across the batch of `toDownload` targets: [6](#0-5) 

Because GitHub's release-asset name uniqueness constraint is presumably byte/case-sensitive, an attacker-controlled release can contain two assets, e.g. `Report.PDF` and `report.pdf` (or NFC/NFD Unicode variants of a filename), that are distinct as far as the GitHub API and this code are concerned but collide to the same inode on a case-insensitive or normalization-folding filesystem. When the victim runs the default (non-`--output`) `gh release download` with the default concurrency of 5, both assets are dispatched to separate worker goroutines. Neither goroutine's `Check`/`check` calls see the other's in-flight write (since the file may not exist yet when both check concurrently, and `os.Stat` provides no locking), so both proceed to `os.OpenFile` with `O_TRUNC` and write. The final on-disk content is whichever asset's `io.Copy` finishes last, and any interleaving of writes during the race window can produce a corrupted mixture of both payloads. No error, conflict message, or need for `--clobber` is ever triggered, silently defeating the "no-overwrite invariant" the `Check`/`--clobber`/`--skip-existing` flags are meant to enforce.

Note: the `--output`/`-O` single-asset path is explicitly guarded and not exploitable this way, since `downloadRun` rejects multiple assets when `OutputFile` is set: [7](#0-6) 
The real reachable path is the default `--dir` (`-D`) multi-asset download flow.

### Impact Explanation
This is a file-write-outside-intended-guarantee bug (silent overwrite / data corruption of a file the CLI's own safeguards were supposed to protect), reachable purely by an attacker publishing a release with two collision-prone asset names — no elevated privileges, tokens, or MITM required. Impact is limited to local file corruption/overwrite of files the victim is deliberately downloading into their own chosen directory; it does not achieve arbitrary path traversal outside `--dir`, code execution, or credential exfiltration, so it maps to a low/moderate "unintended file overwrite" class rather than a critical RCE or credential-disclosure bounty tier.

### Likelihood Explanation
Requires: (1) victim on a case-insensitive or Unicode-normalizing filesystem (default on macOS and Windows — a large fraction of `gh` users), (2) default concurrency of 5 (always the case, it's hardcoded), (3) attacker publishes a release with two asset names that are distinct strings but collide after OS/filesystem normalization, and (4) the victim's local timing causes both `check`s to occur before either write completes. Conditions 1–3 are trivially satisfiable by any GitHub user with release/push access to a public repo the victim is instructed or lured to download from; condition 4 is a genuine data race whose window, while narrow, is repeated on every invocation with colliding names and is amplified because `Check` runs before the network request completes (network latency naturally aligns concurrent goroutines' timing).

### Recommendation
Add a synchronization point in `downloadAssets`/`destinationWriter` that resolves and locks on the OS-normalized destination path (e.g. `filepath.Clean` + case-fold/Unicode-NFC-normalize) before dispatching to workers — either by pre-validating uniqueness of resolved paths across all `toDownload` targets and failing fast with a clear conflict error, or by taking a per-path mutex (e.g. `sync.Map` of in-flight paths) inside `Check`/`Copy` so only one goroutine can hold the check-to-write critical section for a given destination at a time.

### Proof of Concept
Go test sketch for `pkg/cmd/release/download`:
```go
func TestDownloadAssets_ColliconIsRacedOnCaseInsensitiveFS(t *testing.T) {
    // Simulate a case-insensitive filesystem by using a temp dir and
    // asset names that differ only in case: "Asset.txt" and "asset.txt".
    dir := t.TempDir()
    dest := &destinationWriter{dir: dir}

    httpClient := ... // httpmock two GET responses with distinct bodies "AAAA" and "BBBB", each delayed via a small sleep to widen the race window

    targets := []downloadTarget{
        {url: safeurl.NewImmutableSafeURL("https://api.github.com/asset/1"), name: "Asset.txt"},
        {url: safeurl.NewImmutableSafeURL("https://api.github.com/asset/2"), name: "asset.txt"},
    }

    err := downloadAssets(dest, httpClient, targets, 2 /* workers */, false, io)

    // Expectation under a fix: err should be non-nil, reporting a name
    // collision, OR the resulting file's content must deterministically
    // equal exactly one of "AAAA"/"BBBB" with the other write rejected.
    // Under the current (vulnerable) code on a case-insensitive FS stub,
    // this test can observe: err == nil, and the resulting single file's
    // content is either corrupted (partial interleave) or nondeterministic
    // across repeated runs -- demonstrating the missing cross-goroutine
    // synchronization on the resolved destination path.
}
```
Run repeatedly (`go test -race -count=100`) to demonstrate nondeterministic winner/content and confirm no conflict is ever reported by `dest.Check`.

### Citations

**File:** pkg/cmd/release/download/download.go (L217-219)
```go
	if len(toDownload) > 1 && opts.OutputFile != "" {
		return fmt.Errorf("unable to write more than one asset with `--output`, got %d assets", len(toDownload))
	}
```

**File:** pkg/cmd/release/download/download.go (L274-281)
```go
	for w := 1; w <= numWorkers; w++ {
		go func() {
			for a := range jobs {
				io.StartProgressIndicatorWithLabel(fmt.Sprintf("Downloading %s", a.name))
				results <- downloadAsset(dest, httpClient, a.url, a.name, isArchive)
			}
		}()
	}
```

**File:** pkg/cmd/release/download/download.go (L300-303)
```go
func downloadAsset(dest *destinationWriter, httpClient *http.Client, assetURL safeurl.SafeURL, fileName string, isArchive bool) error {
	if err := dest.Check(fileName); err != nil {
		return err
	}
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

**File:** pkg/cmd/release/download/download.go (L379-384)
```go
func (w destinationWriter) makePath(name string) string {
	if w.file == "" {
		return filepath.Join(w.dir, name)
	}
	return w.file
}
```

**File:** pkg/cmd/release/download/download.go (L386-413)
```go
// Check returns an error if a file already exists at destination
func (w destinationWriter) Check(name string) error {
	if name == "" {
		// skip check as file name will only be known after the API request
		return nil
	}
	fp := w.makePath(name)
	if fp == "-" {
		// writing to stdout should always proceed
		return nil
	}
	return w.check(fp)
}

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
