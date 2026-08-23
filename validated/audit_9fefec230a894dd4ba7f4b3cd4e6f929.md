This confirms `Remove` calls `normalizeExtension(name)` before joining, which unconditionally prepends the literal string `"gh-"` unless the name already starts with `"gh-"`.### Title
Path traversal in `Manager.Remove` via `normalizeExtension` allows `os.RemoveAll` to delete files outside `installDir` - ([File: pkg/cmd/extension/manager.go])

### Summary
`Manager.Remove` and `cleanExtensionUpdateDir` build `targetDir`/`UpdateDir` by string-concatenating a literal `"gh-"` prefix onto an attacker-influenced name (via `normalizeExtension`) and then `filepath.Join`-ing it with the base install/update directory. Because the `"gh-"` prefix is merged into the first path segment as plain text rather than as a separate, non-traversable path component, subsequent `..` segments in the name can pop that merged segment off the path stack and continue popping further, letting `filepath.Join`'s `Clean` logic escape `installDir`/`updateDir` entirely before `os.RemoveAll` runs.

### Finding Description
The remove flow is: `pkg/cmd/extension/command.go:466` calls `normalizeExtensionSelector(args[0])`, which only strips text up to the first `/` and trims a leading `"gh-"` if present [1](#0-0)  — it performs no rejection of `..` segments. The result is passed to `m.Remove(extName)` [2](#0-1) .

Inside `Remove`, the name is passed through `normalizeExtension`, which does `name = "gh-" + name` only when the name doesn't already start with `"gh-"` [3](#0-2) . This is a plain string concatenation, not a path-safe operation: if `name` starts with `"../"`, the result is a string like `"gh-../../../../tmp/marker"`, where the first path segment becomes the literal (non-special) component `"gh-.."` — but the `..` segments that follow it in the string are still separate, syntactically valid `".."` path components.

`Remove` then does `targetDir := filepath.Join(m.installDir(), name)` [4](#0-3) . `filepath.Join`/`Clean` processes the path segment-by-segment: the literal `"gh-.."` segment gets pushed onto the resulting path like any ordinary directory name, but the *following* `".."` segments are recognized as parent-directory references and pop that segment (and, if there are enough of them, additional real segments of `installDir` itself) off the stack — allowing the final cleaned path to land outside `installDir`, in a sibling or ancestor directory. The same defect independently affects `cleanExtensionUpdateDir`, which calls `os.RemoveAll(m.UpdateDir(name))` where `UpdateDir` does the identical `filepath.Join(m.updateDir(), normalizeExtension(name))` construction [5](#0-4) [6](#0-5) , and this is invoked from `Remove` before the main `os.RemoveAll(targetDir)` [7](#0-6) .

The only guard present is an `os.Lstat` existence check before deletion [8](#0-7) , which requires the crafted target path to already exist, but does not confine the path to `installDir` (e.g., there is no `filepath.Clean(installDir)`-prefix check on `targetDir`). `installDir`/`updateDir` locations are predictable (standard XDG/AppData paths), so an attacker can construct a traversal string that lands on a directory the victim is likely to have (e.g., a subdirectory of the user's data/config profile).

### Impact Explanation
This allows arbitrary directory/file deletion outside the intended `extensions` (and update-state) directories on the victim's machine, matching GitHub's "unintended data/file destruction outside the sandboxed application directory" bounty impact class. Because `os.RemoveAll` is recursive, the blast radius can include entire directory trees the victim did not intend to delete, causing data loss (denial of service / integrity impact), though not code execution or credential exfiltration directly.

### Likelihood Explanation
Exploitation requires the victim to run `gh extension remove <attacker-suggested-name>` with a name the attacker controls (e.g., copied from a malicious README/tutorial instructing "run `gh extension remove <payload>` to fix an issue"). The attacker must guess an existing path relative to the victim's known, standard install directory layout (feasible for common subdirectories), and craft the exact number of `..` segments needed to land there — this is deterministic and testable offline, but does require some knowledge of the victim's OS/username layout, which lowers but does not eliminate feasibility. No token, MITM, or elevated privileges are required — pure command-line social engineering combined with the parsing bug.

### Recommendation
After computing `targetDir` (and `UpdateDir`), validate confinement explicitly, e.g.:
```go
targetDir := filepath.Join(m.installDir(), name)
if !strings.HasPrefix(targetDir, filepath.Clean(m.installDir())+string(filepath.Separator)) {
    return fmt.Errorf("invalid extension name: %q", name)
}
```
Apply the same check in `UpdateDir`/`cleanExtensionUpdateDir`. Additionally, reject extension names containing path separators or `..` segments at the point of `normalizeExtensionSelector`/`normalizeExtension` rather than relying on later path confinement alone.

### Proof of Concept
```go
func TestManager_Remove_PathTraversal(t *testing.T) {
    tempDir := t.TempDir()
    // simulate installDir/updateDir base one level up
    dataDir := filepath.Join(tempDir, "data")
    require.NoError(t, os.MkdirAll(filepath.Join(dataDir, "extensions"), 0755))
    // create a marker file OUTSIDE the extensions dir, sibling of "gh"
    marker := filepath.Join(tempDir, "data", "tmp", "marker")
    require.NoError(t, os.MkdirAll(filepath.Dir(marker), 0755))
    require.NoError(t, os.WriteFile(marker, []byte("do not delete"), 0644))

    m := newTestManager(dataDir /* installDir() -> dataDir/extensions */, nil, nil, nil)

    // crafted extName as produced by normalizeExtensionSelector for input
    // "gh extension remove x/../../../../tmp/marker"
    extName := "../../../../tmp/marker"

    err := m.Remove(extName)
    // Expect: either an error (rejected), NOT successful deletion of `marker`.
    _, statErr := os.Stat(marker)
    assert.False(t, os.IsNotExist(statErr),
        "marker file outside installDir was deleted via path traversal in Remove")
}
```
Expected (vulnerable) behavior: `marker` is deleted despite residing outside `dataDir/extensions`, demonstrating `PATH_CONFINEMENT` violation. Expected (fixed) behavior: `Remove` returns an error and `marker` remains untouched.

### Citations

**File:** pkg/cmd/extension/command.go (L465-469)
```go
			RunE: func(cmd *cobra.Command, args []string) error {
				extName := normalizeExtensionSelector(args[0])
				if err := m.Remove(extName); err != nil {
					return err
				}
```

**File:** pkg/cmd/extension/command.go (L716-721)
```go
func normalizeExtensionSelector(n string) string {
	if idx := strings.IndexRune(n, '/'); idx >= 0 {
		n = n[idx+1:]
	}
	return strings.TrimPrefix(n, "gh-")
}
```

**File:** pkg/cmd/extension/manager.go (L578-580)
```go
func (m *Manager) Remove(name string) error {
	name = normalizeExtension(name)
	targetDir := filepath.Join(m.installDir(), name)
```

**File:** pkg/cmd/extension/manager.go (L581-583)
```go
	if _, err := os.Lstat(targetDir); os.IsNotExist(err) {
		return fmt.Errorf("no extension found: %q", targetDir)
	}
```

**File:** pkg/cmd/extension/manager.go (L587-590)
```go
	if err := m.cleanExtensionUpdateDir(name); err != nil {
		return err
	}
	return os.RemoveAll(targetDir)
```

**File:** pkg/cmd/extension/manager.go (L597-600)
```go
// UpdateDir returns the extension-specific directory where updates are stored.
func (m *Manager) UpdateDir(name string) string {
	return filepath.Join(m.updateDir(), normalizeExtension(name))
}
```

**File:** pkg/cmd/extension/manager.go (L876-882)
```go
// such as extension manifest and lock files within cli/cli#6118.
func (m *Manager) cleanExtensionUpdateDir(name string) error {
	if err := os.RemoveAll(m.UpdateDir(name)); err != nil {
		return fmt.Errorf("failed to remove previous extension update state: %w", err)
	}
	return nil
}
```

**File:** pkg/cmd/extension/manager.go (L884-890)
```go
// normalizeExtension makes sure that the provided extension name is prefixed with "gh-".
func normalizeExtension(name string) string {
	if !strings.HasPrefix(name, "gh-") {
		name = "gh-" + name
	}
	return name
}
```
