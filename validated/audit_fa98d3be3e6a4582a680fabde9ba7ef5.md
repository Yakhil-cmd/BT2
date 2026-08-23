Based on the code I examined, `opts.IO.Out` is a plain writer with no automatic ANSI-sanitization applied to arbitrary strings — sanitization is only applied when content is explicitly wrapped in `iostreams.Untrusted`, whose `String()` method runs it through `asciisanitizer.Sanitizer` before printing. [1](#0-0)  The gist file content path deliberately wraps `gf.Content` in `iostreams.NewUntrusted(...)` before it can reach `opts.IO.Out`/`opts.IO.ContentOut`. [2](#0-1) 

However, filenames are handled differently: they are collected as raw, untyped `string` values straight from `gist.Files` (a map keyed by filename strings decoded from the JSON API response) and are never wrapped in `Untrusted`. [3](#0-2)  Both listing paths print these raw strings directly:

- `--files` mode: `fmt.Fprintln(opts.IO.Out, fn)` [4](#0-3) 
- Default mode with multiple files: `fmt.Fprintf(opts.IO.Out, "%s\n\n", cs.Muted(fn))` [5](#0-4) 

In the second case, `cs.Muted(fn)` applies ANSI color-formatting codes around the filename but does not strip or sanitize any escape sequences already embedded in `fn` — it simply wraps the string in additional ANSI codes.

### Title
Gist filenames are printed to the terminal without sanitization, allowing ANSI/OSC escape sequence injection - (File: pkg/cmd/gist/view/view.go)

### Summary
`gh gist view` and `gh gist view --files` print filenames sourced directly from the gist API's `Files` map keys without ever routing them through the `iostreams.Untrusted` sanitization wrapper used for file content, unlike `gf.Content`. An attacker who creates a public gist with a filename containing raw ANSI/OSC escape sequences can inject terminal control sequences into a victim's terminal simply by having them run `gh gist view <id>`.

### Finding Description
`viewRun` builds `filenames` directly from `gist.Files` map keys as plain `string` values with no sanitization step. [3](#0-2)  These are then printed via `fmt.Fprintln(opts.IO.Out, fn)` for `--files` mode, and via `fmt.Fprintf(opts.IO.Out, "%s\n\n", cs.Muted(fn))` for the normal multi-file listing header. [6](#0-5)  Neither path wraps `fn` in `iostreams.NewUntrusted`, whereas the content-rendering path explicitly does so and documents the reasoning ("Treat the file content as untrusted external bytes"). [2](#0-1)  `Untrusted.String()` is the only mechanism in this codebase that neutralizes ANSI escape sequences for values printed via `fmt.Fprint`/`Fprintf`/`Fprintln`, via `asciisanitizer.Sanitizer` (with a `stripControl` fallback). [1](#0-0)  Because filenames bypass this wrapper entirely, and `cs.Muted()` only adds color codes without stripping existing ones, any escape sequences embedded in a filename reach the terminal verbatim. GitHub gist filenames are user-controlled strings (map keys from the JSON `files` object), so an attacker can name a file e.g. `"\x1b]8;;https://evil\x07click me\x1b]8;;\x07"` or a `\x1b[2J\x1b[H`-style sequence, and it will be emitted unmodified when the victim runs `gh gist view`.

### Impact Explanation
This allows terminal escape/OSC sequence injection into the victim's terminal session — this can be used to spoof output, hide/rewrite terminal content, or embed clickable OSC-8 hyperlinks that mislead the user, and depending on victim's terminal emulator, more severe escape-sequence-based attacks (e.g., title-bar manipulation, clipboard injection on vulnerable terminals) may be possible. This matches a "terminal escape sequence / output injection" class impact, matching the same threat model the `Untrusted` type and `--allow-escape-sequences` flag were built to defend against for gist content.

### Likelihood Explanation
Fully attacker-controlled and remotely triggerable with no privileges: any GitHub user can create a public gist with an arbitrary filename containing control bytes (GitHub's API generally does not restrict filename byte content), and any victim who runs `gh gist view <id>` or `gh gist view <id> --files` against that gist ID/URL is affected. No special preconditions beyond the victim viewing the attacker's gist.

### Recommendation
Wrap filenames in `iostreams.NewUntrusted(fn)` (or an equivalent sanitizing call) before printing in both the `--files` listing loop and the per-file header (`cs.Muted(...)`) in `viewRun`, consistent with how `gf.Content` is already handled at line 151.

### Proof of Concept
```go
func TestViewRun_FilenameEscapeInjection(t *testing.T) {
    reg := &httpmock.Registry{}
    defer reg.Verify(t)
    reg.Register(
        httpmock.REST("GET", "gists/1234"),
        httpmock.JSONResponse(map[string]interface{}{
            "id": "1234",
            "files": map[string]interface{}{
                "\x1b[31mfake.txt": map[string]interface{}{
                    "content": "hi",
                },
                "clean.txt": map[string]interface{}{
                    "content": "hello",
                },
            },
        }),
    )

    io, _, stdout, _ := iostreams.Test()
    opts := &ViewOptions{
        IO:         io,
        Config:     func() (gh.Config, error) { return config.NewBlankConfig(), nil },
        HttpClient: func() (*http.Client, error) { return &http.Client{Transport: reg}, nil },
        Selector:   "1234",
        ListFiles:  true,
    }

    err := viewRun(opts)
    assert.NoError(t, err)
    assert.NotContains(t, stdout.Bytes(), []byte{0x1b}, "raw ESC byte leaked into terminal output via filename")
}
```
Expected (current, vulnerable) behavior: `stdout.Bytes()` contains the raw `0x1B` byte from the malicious filename, failing the assertion. Expected fixed behavior: filename is sanitized via `Untrusted`, so no raw `0x1B` reaches `opts.IO.Out`.

### Citations

**File:** pkg/iostreams/untrusted.go (L35-44)
```go
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

**File:** pkg/cmd/gist/view/view.go (L148-151)
```go
	render := func(gf *shared.GistFile) error {
		// Treat the file content as untrusted external bytes. The truncated
		// path fetches the full content from the raw URL.
		content := iostreams.NewUntrusted(gf.Content)
```

**File:** pkg/cmd/gist/view/view.go (L217-225)
```go
	showFilenames := len(gist.Files) > 1
	filenames := make([]string, 0, len(gist.Files))
	for fn := range gist.Files {
		filenames = append(filenames, fn)
	}

	sort.Slice(filenames, func(i, j int) bool {
		return strings.ToLower(filenames[i]) < strings.ToLower(filenames[j])
	})
```

**File:** pkg/cmd/gist/view/view.go (L227-237)
```go
	if opts.ListFiles {
		for _, fn := range filenames {
			fmt.Fprintln(opts.IO.Out, fn)
		}
		return nil
	}

	for i, fn := range filenames {
		if showFilenames {
			fmt.Fprintf(opts.IO.Out, "%s\n\n", cs.Muted(fn))
		}
```
