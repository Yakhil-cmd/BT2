### Title
Unsanitized attacker-controlled release tag/URL displayed in extension update banner enables Bidi/zero-width terminal spoofing - (File: pkg/cmd/root/extension.go)

### Summary
`NewCmdExtension`'s `PostRun` prints `releaseInfo.Version` and `releaseInfo.URL` directly via `fmt.Fprintf` with no sanitization step, and these values originate from an attacker-controlled GitHub release `tag_name`/`html_url` (or a git tag/ref for `GitKind` extensions) that can legally contain Unicode bidi-override or zero-width characters, unlike ASCII repository/extension names which GitHub restricts.

### Finding Description
In `NewCmdExtension` [1](#0-0) , the `PostRun` hook writes `ext.Name()`, `ext.CurrentVersion()`, and `releaseInfo.Version`/`releaseInfo.URL` straight to `io.ErrOut` using `fmt.Fprintf` and `cs.Cyan/Yellow` — no call to `asciisanitizer`, `Untrusted.String()`, or any equivalent of the `sanitizeForTerminal` helper used elsewhere in the codebase (e.g. `pkg/cmd/skills/list/list.go`) is present.

`releaseInfo` comes from `checkForExtensionUpdate` → `update.CheckForExtensionUpdate`, which populates `ReleaseInfo{Version: ext.LatestVersion(), URL: ext.URL()}` [2](#0-1) . For a `BinaryKind` extension, `URL()`/`CurrentVersion()`/`LatestVersion()` are sourced from the extension's `manifest.yml`, whose `Tag`/`Name`/`Owner` fields are populated from a GitHub Releases API response — i.e., attacker-controlled `tag_name` and `html_url` fields [3](#0-2) . For a `GitKind` extension, the equivalent version can be a git ref/tag name, which GitHub/git only restricts at the ASCII-control-character level — Unicode RTL-override (U+202E) and zero-width characters are legal in both a release tag name and an `html_url` path segment.

Because none of `ext.Name()`, `ext.CurrentVersion()`, `releaseInfo.Version`, or `releaseInfo.URL` pass through any bidi/zero-width stripping before being interpolated into the terminal banner, an attacker who controls the release/tag metadata of an installed extension repository can inject U+202E (or zero-width joiners) into the tag name or release URL so that the rendered upgrade notice/version string visually reverses or hides parts of the path, making a malicious version/URL appear identical to (or more trustworthy than) the legitimate one.

### Impact Explanation
This enables terminal output spoofing in the "new release available" banner and upgrade command hint printed to the user — a user could be misled about which version/URL/host they are being told to trust when deciding whether to run `gh extension upgrade`. This matches the "Terminal output/prompt spoofing" impact class, though the concrete blast radius here is limited to a notification banner (not a credential prompt or destructive-confirmation flow) — the affected values are display text only and are not fed into any command execution path in this function.

### Likelihood Explanation
Requires that the victim has already installed the attacker's (or a compromised) extension and that a release is published with a crafted `tag_name`, since `NewCmdExtension`'s update check only runs for already-installed extensions. GitHub release tag names and URLs are attacker-controlled and not restricted from containing bidi/zero-width Unicode, so injecting the payload is trivial for the extension publisher; however, the precondition (victim must install the extension first) limits it to a secondary/social-engineering-adjacent scenario rather than a first-contact attack.

### Recommendation
Sanitize all externally-derived display strings (`releaseInfo.Version`, `releaseInfo.URL`, and extension version/tag fields sourced from manifests or git refs) before writing them to the terminal — wrap them in `iostreams.Untrusted` (as done in `pkg/iostreams/untrusted.go`) or extend the existing `asciisanitizer`/`sanitizeForTerminal` pattern to also strip Unicode bidi control characters (U+202A–U+202E, U+2066–U+2069) and zero-width characters (U+200B–U+200D, U+FEFF), not just ASCII control bytes.

### Proof of Concept
```go
// pkg/cmd/root/extension_test.go
func TestNewCmdExtension_PostRun_stripsBidiControls(t *testing.T) {
    ios, _, _, stderr := iostreams.Test()
    ext := &extensions.ExtensionMock{
        NameFunc:           func() string { return "gh-example" },
        CurrentVersionFunc: func() string { return "v1.0.0" },
        IsPinnedFunc:       func() bool { return false },
    }
    maliciousRelease := &update.ReleaseInfo{
        Version: "v1.0.0\u202Egnp.exe", // U+202E reverses trailing text visually
        URL:     "https://github.com/owner/gh-example/releases/tag/v1\u202E0.0",
    }
    checkFn := func(extensions.ExtensionManager, extensions.Extension) (*update.ReleaseInfo, error) {
        return maliciousRelease, nil
    }
    cmd := NewCmdExtension(ios, &extensions.ExtensionManagerMock{}, ext, checkFn)
    cmd.PreRun(cmd, nil)
    _ = cmd.RunE(cmd, nil)
    cmd.PostRun(cmd, nil)

    assert.NotContains(t, stderr.String(), "\u202E", "bidi override character must be stripped before terminal output")
}
```
Expected: with the current implementation this assertion fails because `\u202E` passes through unmodified in the `PostRun` `fmt.Fprintf` calls at `pkg/cmd/root/extension.go:60-70`.

### Citations

**File:** pkg/cmd/root/extension.go (L55-71)
```go
		PostRun: func(c *cobra.Command, args []string) {
			select {
			case releaseInfo := <-updateMessageChan:
				if releaseInfo != nil {
					stderr := io.ErrOut
					fmt.Fprintf(stderr, "\n\n%s %s → %s\n",
						cs.Yellowf("A new release of %s is available:", ext.Name()),
						cs.Cyan(strings.TrimPrefix(ext.CurrentVersion(), "v")),
						cs.Cyan(strings.TrimPrefix(releaseInfo.Version, "v")))
					if ext.IsPinned() {
						fmt.Fprintf(stderr, "To upgrade, run: gh extension upgrade %s --force\n", ext.Name())
					} else {
						fmt.Fprintf(stderr, "To upgrade, run: gh extension upgrade %s\n", ext.Name())
					}
					fmt.Fprintf(stderr, "%s\n\n",
						cs.Yellow(releaseInfo.URL))
				}
```

**File:** internal/update/update.go (L63-66)
```go
	releaseInfo := &ReleaseInfo{
		Version: ext.LatestVersion(),
		URL:     ext.URL(),
	}
```

**File:** pkg/cmd/extension/extension.go (L88-107)
```go
func (e *Extension) CurrentVersion() string {
	e.mu.RLock()
	if e.currentVersion != "" {
		defer e.mu.RUnlock()
		return e.currentVersion
	}
	e.mu.RUnlock()

	var currentVersion string
	switch e.kind {
	case LocalKind:
	case BinaryKind:
		if manifest, err := e.loadManifest(); err == nil {
			currentVersion = manifest.Tag
		}
	case GitKind:
		if sha, err := e.gitClient.CommandOutput([]string{"rev-parse", "HEAD"}); err == nil {
			currentVersion = string(bytes.TrimSpace(sha))
		}
	}
```
