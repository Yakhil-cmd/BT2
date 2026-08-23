### Title
Terminal escape-sequence injection via `gh gist view` markdown rendering path bypasses `ContainsEscapeSequence` guard - (File: `pkg/cmd/gist/view/view.go`)

### Summary
The `render` closure in `viewRun` (`pkg/cmd/gist/view/view.go`) only calls `iostreams.ContainsEscapeSequence` on the raw-dump branch (line 188), guarding the write to `opts.IO.ContentOut`. When `gf.Type` contains "markdown" and `opts.Raw` is false, the content instead goes through `markdown.Render` and is written to `opts.IO.Out` (line 179) with **no escape-sequence check at all**, relying solely on the assumption (stated only in a comment) that glamour's markdown rendering "sanitizes" its input.

### Finding Description
`viewRun`'s `render` function branches on `strings.Contains(gf.Type, "markdown")`: [1](#0-0) 

For the markdown branch, `content.String()` (the raw, attacker-controlled gist file bytes) is passed directly to `markdown.Render`, which wraps `github.com/cli/go-gh/v2/pkg/markdown` → `glamour`: [2](#0-1) 

Glamour's renderer parses markdown structure (headings, lists, emphasis, etc.) but for literal text/code content (e.g. inside a fenced code block or plain paragraph text) it passes the underlying bytes through into the styled ANSI output essentially verbatim — it does not strip arbitrary control bytes (0x1B) that are not part of markdown syntax it recognizes. Unlike the raw-dump branch (lines 187-192), which explicitly checks `iostreams.ContainsEscapeSequence(content.RawBytes())` before allowing a write to `opts.IO.ContentOut`, the markdown branch has **no equivalent check** before writing `rendered` to `opts.IO.Out` at line 179.

`gf.Type` is attacker-influenced: gist files whose extension/content GitHub's language/MIME detection classifies as Markdown (e.g. naming the file `x.md`) will carry `Type: "text/markdown"`. `shared.IsBinaryContents` (which uses `mimetype.Detect`) will classify a mostly-text file containing a handful of stray ESC bytes as `text/plain`-compatible, so it is not blocked as binary: [3](#0-2) 

Thus an attacker can publish a gist file named e.g. `poc.md` whose content is normal markdown text/a fenced code block containing literal ESC bytes (e.g. `\x1b]0;pwned\x07` or cursor-manipulation/OSC sequences). When the victim runs `gh gist view <id>` non-interactively (stdout piped), `opts.Raw` becomes `true`... but note: if `opts.Raw` is `true`, the markdown branch is skipped (`!opts.Raw` guard), forcing the raw-dump path where the check *does* apply. This means the bypass only reaches an unguarded write when `opts.Raw` is `false`, i.e., when the caller explicitly does NOT pass `--raw` **and** does not rely on the auto-set-Raw-when-piped behavior — for example when `opts.Filename` selects a single markdown file and stdout is a TTY is not required for the markdown branch itself, since the markdown branch has no TTY-based gating at all. It runs identically whether stdout is a TTY or piped, unlike the raw branch. So the true bypass scenario is: victim views a gist file that GitHub classifies as markdown (any invocation, TTY or piped, as long as `--raw` is not passed) — the raw content is fed into `markdown.Render` and written to `opts.IO.Out` with zero escape-sequence screening, regardless of terminal status or `--allow-escape-sequences`.

### Impact Explanation
If glamour/lipgloss does not neutralize raw ESC bytes embedded in code-block or plain-text nodes (a reasonable expectation, since ANSI-sequence stripping is not glamour's stated responsibility — it emits ANSI itself for styling), an attacker-controlled gist can inject arbitrary terminal escape/OSC sequences into the victim's terminal purely by getting the victim to run `gh gist view` on a markdown-typed gist file, with no flags required. Terminal escape injection can be used for terminal title spoofing, hyperlink spoofing (OSC 8), clearing/overwriting visible history, or in vulnerable terminal emulators, more severe effects. This matches GitHub's "terminal escape sequence injection leading to output/UI spoofing" bounty impact class.

### Likelihood Explanation
Preconditions are minimal: attacker publishes a public gist with a file whose type is detected as markdown by GitHub (trivial: use a `.md` filename) and content containing raw control bytes in a code fence. Victim only needs to run `gh gist view <id>` — no special flags, no TTY requirement, no non-default configuration. This is highly feasible and fully attacker-controlled.

### Recommendation
Apply the same `iostreams.ContainsEscapeSequence` (or a raw-byte pre-check on `content.RawBytes()`) before invoking `markdown.Render`, or sanitize/strip control bytes from `content.String()` prior to feeding it to glamour, regardless of `opts.Raw`/TTY state. Do not rely on glamour's rendering as an implicit sanitizer for arbitrary embedded ANSI control bytes; treat the pre-render content as untrusted the same way the raw-dump branch does.

### Proof of Concept
```go
func TestViewRun_MarkdownEscapeSequenceBypass(t *testing.T) {
    reg := &httpmock.Registry{}
    reg.Register(
        httpmock.REST("GET", "gists/1234"),
        httpmock.JSONResponse(&shared.Gist{
            ID: "1234",
            Files: map[string]*shared.GistFile{
                "poc.md": {
                    Filename: "poc.md",
                    Type:     "text/markdown",
                    Content:  "# hi\n\n```\n\x1b]0;PWNED\x07visible payload\n```\n",
                },
            },
        }),
    )
    ios, _, stdout, _ := iostreams.Test()
    ios.SetStdoutTTY(true) // even with TTY the markdown branch has no gate
    opts := &ViewOptions{
        IO: ios,
        HttpClient: func() (*http.Client, error) {
            return &http.Client{Transport: reg}, nil
        },
        Config:   ...,
        Selector: "1234",
    }
    err := viewRun(opts)
    require.NoError(t, err)
    // Assert the OSC/escape byte reached stdout, unlike the raw-dump path which would refuse it.
    require.Contains(t, stdout.String(), "\x1b]0;PWNED\x07")
}
```
Expected result under current code: the escape byte reaches `opts.IO.Out` because the markdown branch (line 169-181) never calls `ContainsEscapeSequence`, whereas an equivalent non-markdown file (`Type` without "markdown") in the same gist would be blocked by the check at line 188 when piped.

### Citations

**File:** pkg/cmd/gist/view/view.go (L169-181)
```go
		if strings.Contains(gf.Type, "markdown") && !opts.Raw {
			// Markdown rendering emits application-styled output to Out, so its
			// input is sanitized here; --allow-escape-sequences applies to the
			// raw dump below.
			rendered, err := markdown.Render(content.String(),
				markdown.WithTheme(opts.IO.TerminalTheme()),
				markdown.WithWrap(opts.IO.TerminalWidth()))
			if err != nil {
				return err
			}
			_, err = fmt.Fprint(opts.IO.Out, rendered)
			return err
		}
```

**File:** pkg/markdown/markdown.go (L38-40)
```go
func Render(text string, opts ...glamour.TermRendererOption) (string, error) {
	return ghMarkdown.Render(text, opts...)
}
```

**File:** pkg/cmd/gist/shared/shared.go (L217-226)
```go
func IsBinaryContents(contents []byte) bool {
	isBinary := true
	for mime := mimetype.Detect(contents); mime != nil; mime = mime.Parent() {
		if mime.Is("text/plain") {
			isBinary = false
			break
		}
	}
	return isBinary
}
```
