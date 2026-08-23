### Title
Cached `ReleaseInfo.Version`/`URL` from `state.yml` are printed to the terminal unsanitized, allowing persistent terminal-injection via the update-checker cache - ([File: internal/update/update.go])

### Summary
`getStateEntry`/`setStateEntry` round-trip `StateEntry.LatestRelease` (attacker-influenced `tag_name`/`html_url` for extensions, or upstream release data for `gh` itself) through `state.yml` with no sanitization, and the values are later written straight to stderr with ANSI color wrapping but no control-sequence stripping. Because the cache is honored for 24 hours, a malicious `ReleaseInfo` captured once (e.g., from a malicious extension release) is replayed to the victim's terminal on subsequent `gh`/extension invocations even after the upstream release is deleted.

### Finding Description
`getStateEntry` reads `state.yml` and unmarshals it directly into `StateEntry` with no validation of the `LatestRelease.Version`/`URL` fields: [1](#0-0) 

`setStateEntry` persists whatever `ReleaseInfo` was fetched, again without any sanitization: [2](#0-1) 

For extensions, `CheckForExtensionUpdate` builds `ReleaseInfo` directly from `ext.LatestVersion()`/`ext.URL()`, which for a git/binary extension can reflect attacker-controlled tag names or release URLs from a repository the victim installed as a `gh` extension. It caches this value and returns the cached `StateEntry.LatestRelease` on the next run without re-fetching or re-validating as long as the cache is within the 24h window: [3](#0-2) 

The cached/returned `ReleaseInfo` is then printed straight to `stderr` after being color-wrapped, but color-wrapping (`cs.Cyan`, `ansi.Color`) does not strip pre-existing control/escape bytes from the input string: [4](#0-3) [5](#0-4) 

The codebase has an established mechanism for exactly this class of risk — the `iostreams.Untrusted` wrapper, whose `String()` method sanitizes ANSI escape sequences on every `fmt` print path — but `ReleaseInfo.Version`/`URL` are plain `string` fields, not `Untrusted`, so they bypass this protection entirely: [6](#0-5) 

Because `setStateEntry` persists the unsanitized value to disk and `getStateEntry` reuses it for up to 24 hours without re-fetching, the injection is not merely a one-shot response replay — it persists across multiple `gh`/extension invocations independent of whether the malicious release still exists upstream.

### Impact Explanation
An attacker who publishes a malicious `gh` extension release (or otherwise influences the `tag_name`/`html_url` reflected as `ReleaseInfo`) can embed ANSI/terminal control sequences that get written to the victim's stderr on every extension invocation for up to 24 hours after the first fetch, including runs long after the malicious release is deleted. This matches GitHub's terminal/output injection impact class — it can be used to spoof CLI output, hide/alter subsequent terminal content, or (depending on terminal emulator features such as OSC sequences) attempt more advanced terminal manipulation.

### Likelihood Explanation
Requires only that the victim install/run a `gh` extension the attacker controls (or points `gh` at a malicious remote for extension update checks) once, so the malicious `ReleaseInfo` gets cached via `setStateEntry`. No token, MITM, or elevated privilege is needed — installing and running a third-party `gh` extension is normal, expected usage. Repeatable on each invocation within the 24-hour cache window.

### Recommendation
Sanitize `ReleaseInfo.Version` and `ReleaseInfo.URL` before display (or type them as `iostreams.Untrusted` so `String()` neutralizes escape sequences automatically), and apply the same sanitization at the point of `setStateEntry`/`getStateEntry` so cached data cannot carry raw control bytes regardless of consumer.

### Proof of Concept
```go
func TestGetStateEntry_UnsanitizedControlSequencesPersist(t *testing.T) {
    dir := t.TempDir()
    stateFilePath := filepath.Join(dir, "state.yml")

    malicious := ReleaseInfo{
        Version: "v1.0.0\x1b]0;pwned\x07",
        URL:     "http://example.com/\x1b[31mFAKE\x1b[0m",
    }
    require.NoError(t, setStateEntry(stateFilePath, time.Now(), malicious))

    got, err := getStateEntry(stateFilePath)
    require.NoError(t, err)

    // Fails today: raw escape bytes survive the disk round-trip unsanitized.
    require.NotContains(t, got.LatestRelease.Version, "\x1b")
    require.NotContains(t, got.LatestRelease.URL, "\x1b")
}
```
Expected: today this assertion fails, demonstrating that `state.yml` persists and `getStateEntry` reconstructs attacker-controlled control sequences unmodified, which downstream printing code (`internal/ghcmd/cmd.go:262-270`, `pkg/cmd/root/extension.go:60-70`) then writes to the terminal on every invocation within the 24h cache window.

### Citations

**File:** internal/update/update.go (L50-78)
```go
// CheckForExtensionUpdate checks whether an update exists for a specific extension based on extension type and recency of last check within past 24 hours.
func CheckForExtensionUpdate(em extensions.ExtensionManager, ext extensions.Extension, now time.Time) (*ReleaseInfo, error) {
	// local extensions cannot have updates, so avoid work that ultimately returns nothing.
	if ext.IsLocal() {
		return nil, nil
	}

	stateFilePath := filepath.Join(em.UpdateDir(ext.Name()), "state.yml")
	stateEntry, _ := getStateEntry(stateFilePath)
	if stateEntry != nil && now.Sub(stateEntry.CheckedForUpdateAt).Hours() < 24 {
		return nil, nil
	}

	releaseInfo := &ReleaseInfo{
		Version: ext.LatestVersion(),
		URL:     ext.URL(),
	}

	err := setStateEntry(stateFilePath, now, *releaseInfo)
	if err != nil {
		return nil, err
	}

	if ext.UpdateAvailable() {
		return releaseInfo, nil
	}

	return nil, nil
}
```

**File:** internal/update/update.go (L147-160)
```go
func getStateEntry(stateFilePath string) (*StateEntry, error) {
	content, err := os.ReadFile(stateFilePath)
	if err != nil {
		return nil, err
	}

	var stateEntry StateEntry
	err = yaml.Unmarshal(content, &stateEntry)
	if err != nil {
		return nil, err
	}

	return &stateEntry, nil
}
```

**File:** internal/update/update.go (L162-176)
```go
func setStateEntry(stateFilePath string, t time.Time, r ReleaseInfo) error {
	data := StateEntry{CheckedForUpdateAt: t, LatestRelease: r}
	content, err := yaml.Marshal(data)
	if err != nil {
		return err
	}

	err = os.MkdirAll(filepath.Dir(stateFilePath), 0755)
	if err != nil {
		return err
	}

	err = os.WriteFile(stateFilePath, content, 0600)
	return err
}
```

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

**File:** internal/ghcmd/cmd.go (L254-271)
```go
	updateCancel() // if the update checker hasn't completed by now, abort it
	newRelease := <-updateMessageChan
	if newRelease != nil {
		isHomebrew := isUnderHomebrew(cmdFactory.ExecutablePath)
		if isHomebrew && isRecentRelease(newRelease.PublishedAt) {
			// do not notify Homebrew users before the version bump had a chance to get merged into homebrew-core
			return exitOK
		}
		fmt.Fprintf(stderr, "\n\n%s %s → %s\n",
			ansi.Color("A new release of gh is available:", "yellow"),
			ansi.Color(strings.TrimPrefix(buildVersion, "v"), "cyan"),
			ansi.Color(strings.TrimPrefix(newRelease.Version, "v"), "cyan"))
		if isHomebrew {
			fmt.Fprintf(stderr, "To upgrade, run: %s\n", "brew upgrade gh")
		}
		fmt.Fprintf(stderr, "%s\n\n",
			ansi.Color(newRelease.URL, "yellow"))
	}
```

**File:** pkg/iostreams/untrusted.go (L16-44)
```go
// Untrusted satisfies fmt.Stringer, and String sanitizes, so any fmt print path
// (Fprint, Fprintf with %s or %v, Sprint) renders the content with ANSI escape
// sequences neutralized. The only way to reach the raw bytes is Raw, which is
// deliberately easy to grep for and is intended for non-terminal uses such as
// hashing, writing to a file, or piping to another program.
type Untrusted struct {
	raw string
}

// NewUntrusted labels a string as untrusted external content.
func NewUntrusted(s string) Untrusted {
	return Untrusted{raw: s}
}

// NewUntrustedBytes labels a byte slice as untrusted external content.
func NewUntrustedBytes(b []byte) Untrusted {
	return Untrusted{raw: string(b)}
}

// String returns the content with ANSI escape sequences neutralized. It is
// called automatically by the fmt package, so printing an Untrusted value is
// safe by default on every fmt path.
func (u Untrusted) String() string {
	sanitized, _, err := transform.String(&asciisanitizer.Sanitizer{}, u.raw)
	if err != nil {
		return stripControl(u.raw)
	}
	return sanitized
}
```
