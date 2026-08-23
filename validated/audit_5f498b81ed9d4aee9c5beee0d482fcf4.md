### Title
Unsanitized rendering of untrusted GitHub issue/PR titles to the terminal allows ANSI escape-sequence injection - (File: `pkg/cmd/issue/view/view.go`, `pkg/cmd/pr/view/view.go`)

### Summary
`gh` deliberately built a hardened terminal-output pipeline (`iostreams.Untrusted`, `ContainsEscapeSequence`, `asciisanitizer`) specifically to neutralize ANSI/OSC escape sequences that could arrive in externally-authored content (gist files, downloaded release assets, `read-file` output, diffs) before it reaches the user's terminal. [1](#0-0) [2](#0-1)  However, `issue.Title` / `pr.Title` — which is attacker-controlled content fetched directly from the GitHub API (any user can open an issue/PR with an arbitrary title on any public repo) — is printed with plain `fmt.Fprintf` straight to `opts.IO.Out`, bypassing all of these sanitization mechanisms.

### Finding Description
In `printRawIssuePreview` and `printHumanIssuePreview`, the issue title is written directly to the writer with no escaping:
```go
fmt.Fprintf(out, "title:\t%s\n", issue.Title)
...
fmt.Fprintf(out, "%s %s#%d\n", cs.Bold(issue.Title), ghrepo.FullName(baseRepo), issue.Number)
``` [3](#0-2) [4](#0-3) 

The same pattern is used for pull request titles in `pkg/cmd/pr/view/view.go` (title header printing).

Compare this to how the codebase treats other external content: gist file bodies are wrapped in `iostreams.Untrusted`, whose `String()` runs the payload through `asciisanitizer` before any `fmt` verb can leak raw bytes, and `Raw()` is an explicit, greppable opt-out reserved for non-terminal sinks. [5](#0-4)  Raw text/diff/file content downloaded from GitHub is explicitly checked with `iostreams.ContainsEscapeSequence` and refused or written only through the escape-stripping `ContentOut` writer. [6](#0-5) [7](#0-6)  Even the newer Skills listing feature explicitly sanitizes untrusted frontmatter fields before putting them in a table. [8](#0-7) 

Issue/PR titles are structurally identical untrusted content (author-controlled string from a remote GitHub resource) but are excluded from this model — they are printed via `opts.IO.Out`/`cs.Bold(...)` directly, not `opts.IO.ContentOut`, and never pass through `Untrusted.String()` or `ContainsEscapeSequence`. This is the same root-cause pattern as the Sablier bug: content controlled by an untrusted party is embedded into a rendering surface (terminal instead of SVG/DOM) without stripping the characters that give that surface its "active" behavior (ANSI/OSC control sequences instead of `<`/`>`).

### Impact Explanation
An attacker who can create/comment on/open a public issue or pull request (a fully unprivileged, unauthenticated-relative-to-the-victim action, since anyone can open issues on public repos) can set the title to a string embedding ANSI/OSC escape sequences. When a victim runs an ordinary `gh` command against that repo — `gh issue view`, `gh pr view`, or list/status views that print the title — the escape sequences are emitted verbatim to the victim's terminal. Depending on the victim's terminal emulator, this enables:
- OSC 0/2 "set title" sequences to spoof the window/tab title for phishing.
- OSC 8 hyperlink escapes to render deceptive clickable text.
- Cursor-movement/erase sequences to hide or rewrite previously displayed output, misleading the user about what they approved/reviewed.
- On terminals with known escape-sequence vulnerabilities (clipboard write via OSC 52, or historically exploitable emulators), this can lead to more serious outcomes such as clipboard poisoning.

This does not achieve arbitrary code execution in `gh` itself, but it is a genuine unprivileged remote-attacker-controlled terminal-injection primitive matching the category explicitly in scope ("untrusted terminal output").

### Likelihood Explanation
High reachability: viewing any issue/PR is one of the most common `gh` operations, and titles are always displayed without any confirmation step or opt-out flag (unlike gist/diff/file content, which has a documented `--allow-escape-sequences` model with sanitization-by-default). No special conditions are needed beyond the attacker being able to create an issue/PR with a chosen title on a repository the victim will later view with `gh`.

### Recommendation
Route `issue.Title` / `pr.Title` (and any other free-text metadata fields sourced from the GitHub API and printed outside of `ContentOut`, e.g. labels, milestone titles, discussion titles) through the same `iostreams.Untrusted` sanitization path already used for gist and file content, or apply the `asciisanitizer` transform before interpolating them into `fmt.Fprintf` calls that target `opts.IO.Out`. This aligns title rendering with the pattern already established in `pkg/iostreams/untrusted.go` and `pkg/cmd/skills/list/list.go`'s `sanitizeForTerminal`.

### Proof of Concept
1. On any repository, open an issue with the title:
   `Legit issue\x1b]0;pwned\x07` (or an OSC 8 hyperlink payload embedding deceptive link text).
2. Victim runs `gh issue view <number> --repo <owner>/<repo>` in an interactive terminal.
3. `printHumanIssuePreview` executes `fmt.Fprintf(out, "%s %s#%d\n", cs.Bold(issue.Title), ...)` [9](#0-8) , writing the raw escape bytes to `opts.IO.Out`, which — unlike `opts.IO.ContentOut` — performs no ANSI stripping.
4. The victim's terminal emulator interprets the embedded OSC/CSI sequence (e.g., renaming the terminal title, rendering a fake hyperlink, or manipulating on-screen content), all triggered by a completely unprivileged, remote attacker's issue title.

### Citations

**File:** pkg/iostreams/untrusted.go (L11-20)
```go
// Untrusted wraps string content the application did not author: HTTP response
// bodies, file contents fetched from a remote, anything that originates outside
// the CLI. The raw bytes are unexported so the only ways out are the methods
// below.
//
// Untrusted satisfies fmt.Stringer, and String sanitizes, so any fmt print path
// (Fprint, Fprintf with %s or %v, Sprint) renders the content with ANSI escape
// sequences neutralized. The only way to reach the raw bytes is Raw, which is
// deliberately easy to grep for and is intended for non-terminal uses such as
// hashing, writing to a file, or piping to another program.
```

**File:** pkg/iostreams/untrusted.go (L35-51)
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

// Raw returns the unsanitized content. It is the explicit, greppable opt-out
// for non-terminal uses (hashing, writing to disk, piping). Never pass the
// result to a terminal writer.
func (u Untrusted) Raw() string {
	return u.raw
}
```

**File:** pkg/iostreams/content.go (L16-20)
```go
// ContainsEscapeSequence reports whether b contains an ANSI escape byte (0x1B),
// which can manipulate a terminal when printed.
func ContainsEscapeSequence(b []byte) bool {
	return bytes.IndexByte(b, 0x1B) >= 0
}
```

**File:** pkg/cmd/issue/view/view.go (L204-204)
```go
	fmt.Fprintf(out, "title:\t%s\n", issue.Title)
```

**File:** pkg/cmd/issue/view/view.go (L240-245)
```go
func printHumanIssuePreview(opts *ViewOptions, baseRepo ghrepo.Interface, issue *api.Issue) error {
	out := opts.IO.Out
	cs := opts.IO.ColorScheme()

	// Header (Title and State)
	fmt.Fprintf(out, "%s %s#%d\n", cs.Bold(issue.Title), ghrepo.FullName(baseRepo), issue.Number)
```

**File:** pkg/cmd/repo/read-file/read_file.go (L196-200)
```go
	// Refuse terminal escape sequences unless --allow-escape-sequences, in both TTY and non-TTY modes,
	// so a malicious file cannot manipulate a downstream terminal.
	if !opts.AllowEscapeSequences && iostreams.ContainsEscapeSequence(file.Content) {
		return errors.New("file contains terminal escape sequences; use --allow-escape-sequences to read anyway")
	}
```

**File:** pkg/cmd/pr/diff/diff.go (L174-204)
```go
	// A terminal shows escape sequences inert through ContentOut; piped output is
	// faithful, so a diff carrying escape sequences is refused rather than silently
	// altered. --allow-escape-sequences streams raw on both. The colored path
	// always neutralizes, since it is terminal-bound.
	if opts.AllowEscapeSequences {
		opts.IO.SetContentSanitization(false)
	}

	if err := opts.IO.StartPager(); err == nil {
		defer opts.IO.StopPager()
	} else {
		fmt.Fprintf(opts.IO.ErrOut, "failed to start pager: %v\n", err)
	}

	if opts.NameOnly {
		return changedFilesNames(opts.IO.ContentOut, diff)
	}

	if opts.UseColor {
		return colorDiffLines(opts.IO.Out, sanitizedReader(diff))
	}

	if !opts.AllowEscapeSequences && !opts.IO.IsStdoutTTY() {
		data, err := io.ReadAll(diff)
		if err != nil {
			return err
		}
		if iostreams.ContainsEscapeSequence(data) {
			return errors.New("the diff contains terminal escape sequences; pass --allow-escape-sequences to output it anyway")
		}
		opts.IO.SetContentSanitization(false)
```

**File:** pkg/cmd/skills/list/list.go (L520-529)
```go
// sanitizeForTerminal replaces ASCII control characters in s with inert
// caret-style stand-ins so frontmatter values cannot inject terminal escapes.
func sanitizeForTerminal(s string) string {
	var buf bytes.Buffer
	r := transform.NewReader(bytes.NewReader([]byte(s)), &asciisanitizer.Sanitizer{})
	if _, err := io.Copy(&buf, r); err != nil {
		return "Unknown"
	}
	return buf.String()
}
```
