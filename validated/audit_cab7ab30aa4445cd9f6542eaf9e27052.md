### Title
Path traversal via crafted release asset name in `gh release download` - ([File: pkg/cmd/release/download/download.go])

### Summary
`downloadRun` builds `downloadTarget.name` directly from the server-supplied `ReleaseAsset.Name` field (from the GitHub REST/GraphQL release JSON), and `destinationWriter.makePath` joins that untrusted name with `opts.Destination` using `filepath.Join` without any traversal sanitization. An attacker who publishes a release with an asset whose `name` contains sequences like `../../evil` can cause `gh release download` to write the asset outside the user-specified `--dir`/`--destination` directory.

### Finding Description
`downloadRun` iterates `release.Assets` and copies `a.Name` verbatim into `downloadTarget{name: a.Name}` [1](#0-0) . `release.Assets` is populated by decoding the server JSON response into `shared.Release`/`shared.ReleaseAsset`, where `Name` has no validation, format restriction, or sanitization applied at decode time [2](#0-1) [3](#0-2) .

This name flows through `downloadAssets` → `downloadAsset(dest, httpClient, a.url, a.name, isArchive)` → `dest.Check(fileName)` and `dest.Copy(fileName, resp.Body)` [4](#0-3) [5](#0-4) .

Both `Check` and `Copy` call `makePath(name)`, which simply does `filepath.Join(w.dir, name)` with no confinement check (no `filepath.Rel`, no prefix check against `w.dir`, no rejection of `..` segments, no `safepaths`-style helper) [6](#0-5) . Since `filepath.Join` only lexically cleans a path and does not prevent the resulting path from resolving outside `w.dir` when `name` contains leading `../` sequences, a name such as `../../evil` combined with `dir="."` yields a path outside the intended destination.

`Copy` then creates any necessary parent directories via `os.MkdirAll(dir, 0755)` and writes the file with `os.OpenFile(fp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)` at that resolved path [7](#0-6) , meaning the traversal is not just theoretical — it directly results in a file write (with directory creation) at an attacker-chosen relative location outside `opts.Destination`.

The only filename-based validation present is the Windows reserved-filename check (`isWindowsReservedFilename`), which only compares the base name after splitting on `.` and does not address path traversal at all [8](#0-7) [9](#0-8) . There is no `--pattern`-only restriction here: the vulnerable path is reached for every asset in `release.Assets`, whether or not `--pattern` is used, since the filter (`matchAny`) only decides *whether* to download an asset, not how its name is sanitized before being joined into a filesystem path [10](#0-9) .

Note: when `--output`/`-O` is used (single asset), `w.file` is set and `makePath` returns `w.file` directly, bypassing the vulnerable join entirely [11](#0-10) . The vulnerability applies to the default `--dir`/`-D` flow, which is also the default behavior with no flags.

### Impact Explanation
This is an arbitrary file write outside the intended destination directory, controlled entirely by the content of a GitHub release published by an attacker-controlled/public repository. A victim running `gh release download` (or `gh release download v1.2.3`) against such a repo can have files written to arbitrary relative paths outside `--dir`/`-D` (default `.`), including creation of new parent directories via `MkdirAll`. Depending on the working directory the victim runs `gh` from and the attacker-chosen relative traversal depth, this can overwrite existing files (e.g., shell profile files, other project files) reachable via relative path traversal, corresponding to the "arbitrary file write" bounty impact class. It does not achieve absolute-path writes directly (since `filepath.Join` is used, not raw concatenation) — but relative traversal (`../../../etc/foo` style, bounded by chdir context) is directly reachable.

### Likelihood Explanation
Fully unprivileged and remotely triggerable: any GitHub user can create a public repository and publish a release with an asset name set via the standard release-asset upload API (asset `name` is attacker-controlled metadata, not derived from the uploaded file's actual filename). The victim simply needs to run `gh release download` against that repo — a common, expected workflow, requiring no special victim configuration. This is highly repeatable and requires no race conditions or timing.

### Recommendation
In `destinationWriter.makePath` (or before calling it), reject or sanitize asset names that are absolute, contain `..` path segments, or whose joined-and-cleaned result escapes `w.dir`. E.g., compute `filepath.Clean(name)`, reject if it starts with `..` or is absolute, and/or verify with `filepath.Rel(w.dir, fp)` that the result does not start with `..` before proceeding to `Check`/`Copy`. Apply the same restriction to the archive/`Content-Disposition`-derived filename path (already using `filepath.Base`, which is safer, but the asset-name path is not).

### Proof of Concept
```go
func TestDownloadRun_MaliciousAssetNameTraversal(t *testing.T) {
    reg := &httpmock.Registry{}
    defer reg.Verify(t)

    shared.StubFetchRelease(t, reg, "OWNER", "REPO", "v1.2.3", `
    { "tag_name": "v1.2.3",
      "assets": [
        { "url": "https://api.github.com/assets/1234", "name": "../../evil", "size": 12 }
      ] }`)

    reg.Register(
        httpmock.REST("GET", "assets/1234"),
        httpmock.StringResponse("MALICIOUS"))

    tempDir := t.TempDir()
    subDir := filepath.Join(tempDir, "dest")
    require.NoError(t, os.MkdirAll(subDir, 0755))

    opts := &DownloadOptions{
        IO:         iostreams.Test().IOStreams,
        HttpClient: func() (*http.Client, error) { return &http.Client{Transport: reg}, nil },
        BaseRepo:   func() (ghrepo.Interface, error) { return ghrepo.New("OWNER", "REPO"), nil },
        TagName:     "v1.2.3",
        Destination: subDir,
        Concurrency: 1,
    }

    err := downloadRun(opts)
    require.NoError(t, err)

    // Expected (secure) behavior: file must remain within subDir.
    escapedPath := filepath.Join(tempDir, "evil") // two levels up from subDir
    _, statErr := os.Stat(escapedPath)
    require.NoError(t, statErr, "asset should NOT have escaped destination directory, but it did")
}
```
Expected result on the current code: the file is written at `tempDir/evil` (outside `subDir`), confirming the escape. A fixed implementation should either error out (`Check`/`Copy` returning a path-confinement error) or write the file safely within `subDir` only.

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

**File:** pkg/cmd/release/download/download.go (L379-384)
```go
func (w destinationWriter) makePath(name string) string {
	if w.file == "" {
		return filepath.Join(w.dir, name)
	}
	return w.file
}
```

**File:** pkg/cmd/release/download/download.go (L416-417)
```go
func (w destinationWriter) Copy(name string, r io.Reader) (copyErr error) {
	fp := w.makePath(name)
```

**File:** pkg/cmd/release/download/download.go (L435-452)
```go
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
```

**File:** pkg/cmd/release/download/download.go (L456-474)
```go
func isWindowsReservedFilename(filename string) bool {
	// Windows terminals should prevent the creation of these files
	// but that behavior is not enforced across terminals. Prevent
	// the user from downloading files with these reserved names as
	// they represent an exploit vector for bad actors.
	// Reserved filenames defined at:
	// https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#win32-file-namespaces
	reservedFilenames := []string{"CON", "PRN", "AUX", "NUL", "COM0",
		"COM1", "COM2", "COM3", "COM4", "COM5",
		"COM6", "COM7", "COM8", "COM9", "COM¹",
		"COM²", "COM³", "LPT0", "LPT1", "LPT2",
		"LPT3", "LPT4", "LPT5", "LPT6", "LPT7",
		"LPT8", "LPT9", "LPT¹", "LPT²", "LPT³"}

	// Normalize type case and remove file type extension from filename.
	filename = strings.ToUpper(strings.Split(filename, ".")[0])

	return slices.Contains(reservedFilenames, filename)
}
```

**File:** pkg/cmd/release/shared/fetch.go (L73-87)
```go
type ReleaseAsset struct {
	ID     string `json:"node_id"`
	Name   string
	Label  string
	Size   int64
	Digest *string
	State  string
	APIURL string `json:"url"`

	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	DownloadCount      int       `json:"download_count"`
	ContentType        string    `json:"content_type"`
	BrowserDownloadURL string    `json:"browser_download_url"`
}
```

**File:** pkg/cmd/release/shared/fetch.go (L300-303)
```go
	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}
```
