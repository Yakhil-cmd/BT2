### Title
Path traversal in `writeToOutput` via unsanitized `file.Name` from Contents API response - (File: `pkg/cmd/repo/read-file/read_file.go`)

### Summary
`writeToOutput` in `pkg/cmd/repo/read-file/read_file.go` joins the API-provided `file.Name` directly into the output directory with `filepath.Join(dest, file.Name)` when `--output` targets a directory, with no traversal-confinement check comparable to `internal/safepaths.Absolute.Join` used elsewhere in the codebase (e.g. `internal/zip/zip.go`, `internal/skills/installer/installer.go`). `file.Name` originates verbatim from the `name` JSON field of the GitHub Contents API response, decoded without validation in `pkg/cmd/repo/read-file/http.go`'s `fetchFile`.

### Finding Description
The call chain is: `readFileRun` → `fetchFile` (`http.go:128-172`) populates `repoFile.Name` directly from `contentsResponse.Name`, i.e. the JSON `"name"` field of the API response body, with no sanitization [1](#0-0) . This value flows into `writeToOutput`, where, if the `--output` argument resolves to a directory (`asDir == true`), the destination path is computed as `filepath.Join(dest, file.Name)` [2](#0-1) . The only safety check performed afterward is an `lstatF` symlink check on the final joined path [3](#0-2) ; there is no confinement check that the resulting path stays inside `dest`, unlike the pattern used in `internal/safepaths.Absolute.Join`, which explicitly rejects joins that escape the base directory via `isSubpathOf` [4](#0-3) , and which is used by `internal/zip/zip.go` and `internal/skills/installer/installer.go` but not here.

For real github.com repositories, git tree entry names cannot practically contain literal `/` or `..` path-traversal sequences through normal git tooling, since a `/` in a tree entry name is what creates a subdirectory rather than a literal character in a leaf name — so exploiting this against genuine github.com-hosted content would require GitHub's backend to fail to sanitize a malformed low-level git tree object, which cannot be verified from this codebase alone. However, per the stated threat model that includes "a host the victim points gh at" (e.g. a GitHub Enterprise-compatible or custom host configured by the victim), the `name` field is fully attacker-controlled JSON with zero validation on the client side, so a malicious/compromised host can trivially return `"name": "../../../.ssh/authorized_keys"` (or similar) for any requested contents lookup, causing `writeToOutput` to write attacker-supplied content outside the user-specified output directory.

### Impact Explanation
This is an arbitrary file write outside the intended output directory, scoped to whatever writable path is reachable via `../` traversal and process file permissions when the victim runs `gh repo read-file <path> --output some-dir/`. This maps to GitHub's "File write or overwrite outside the intended path" bounty impact class. The impact is bounded by the fact that content and destination filename must both be attacker-influenced; on real github.com this is not straightforwardly exploitable due to git's own naming constraints, so the concretely reachable case is limited to a victim-configured malicious/custom host scenario.

### Likelihood Explanation
Requires: (1) the victim runs `gh repo read-file <path> --output <dir>/` (trailing separator, or existing directory) against a repository/host the attacker controls the Contents API responses for, and (2) that response's `name` field contains path-traversal segments. This is trivially reproducible against a custom/malicious host via `httpmock`, but reproducing it against genuine github.com-hosted repository content is not demonstrated to be feasible with this codebase alone, since it would depend on GitHub server-side git-object validation behavior that is outside the scope of this repo.

### Recommendation
In `writeToOutput`, before joining `file.Name` into `dest`, sanitize it (e.g. `filepath.Base(file.Name)`) and/or use `internal/safepaths.Absolute.Join` to validate that the resulting path is confined to the user-specified output directory, consistent with `internal/zip/zip.go` and `internal/skills/installer/installer.go`, and reject or error out if `file.Name` contains path separators or `..` segments.

### Proof of Concept
```go
// pkg/cmd/repo/read-file/read_file_test.go (illustrative addition)
func TestWriteToOutput_PathTraversalInName(t *testing.T) {
    dir := t.TempDir()
    file := &repoFile{
        Name:    "../../evil.txt", // attacker-controlled via Contents API "name" field
        Content: []byte("pwned"),
    }
    dest, err := writeToOutput(file, dir+string(os.PathSeparator), false)
    require.NoError(t, err)
    // Assert failure of confinement: dest resolves outside dir
    absDir, _ := filepath.Abs(dir)
    absDest, _ := filepath.Abs(dest)
    rel, _ := filepath.Rel(absDir, absDest)
    require.True(t, strings.HasPrefix(rel, ".."),
        "expected write to escape output directory, got dest=%s", dest)
}
```
An `httpmock`-based end-to-end variant would stub the Contents API GET response with `"name": "../../evil.txt"` and assert that `gh repo read-file <path> --output some-dir/` writes the file outside `some-dir/`.

### Citations

**File:** pkg/cmd/repo/read-file/http.go (L150-161)
```go
	file := &repoFile{
		Name:        content.Name,
		Path:        content.Path,
		SHA:         content.SHA,
		Size:        content.Size,
		URL:         content.URL,
		HTMLURL:     content.HTMLURL,
		GitURL:      content.GitURL,
		DownloadURL: content.DownloadURL,
		Type:        content.Type,
		Encoding:    content.Encoding,
	}
```

**File:** pkg/cmd/repo/read-file/read_file.go (L278-280)
```go
	if asDir {
		dest = filepath.Join(dest, file.Name)
	}
```

**File:** pkg/cmd/repo/read-file/read_file.go (L282-291)
```go
	if lr, err := lstatF(dest); err == nil {
		if lr.isSymlink {
			return "", fmt.Errorf("output path is a symlink")
		}
		if !clobber {
			return "", fmt.Errorf("output path already exists: %q (use --clobber to overwrite)", dest)
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
```

**File:** internal/safepaths/absolute.go (L38-57)
```go
func (a Absolute) Join(elem ...string) (Absolute, error) {
	joinedAbsolutePath, err := ParseAbsolute(filepath.Join(append([]string{a.path}, elem...)...))
	if err != nil {
		return Absolute{}, fmt.Errorf("failed to parse joined path: %w", err)
	}

	isSubpath, err := joinedAbsolutePath.isSubpathOf(a)
	if err != nil {
		return Absolute{}, err
	}

	if !isSubpath {
		return Absolute{}, PathTraversalError{
			Base:  a,
			Elems: elem,
		}
	}

	return joinedAbsolutePath, nil
}
```
