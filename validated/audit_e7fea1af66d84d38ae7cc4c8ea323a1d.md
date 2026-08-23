### Title
Unsanitized attacker-controlled tree entry names allow terminal escape/prompt injection in `gh repo read-dir` - ([File: pkg/cmd/repo/read-dir/read_dir.go])

### Summary
`writeTable` in `pkg/cmd/repo/read-dir/read_dir.go` passes `e.Name` directly into `tp.AddField` without any sanitization of ANSI/control bytes, unlike other list renderers in this codebase (e.g. `pkg/cmd/skills/list/list.go`) that explicitly call `sanitizeForTerminal` using `asciisanitizer` before rendering untrusted, attacker-controlled strings to a TTY. Since `dirEntry.Name` originates from the GraphQL `Tree.Entries.Name` field of an attacker-controlled repository/ref, an attacker can craft a file/dir name containing OSC 8 hyperlink sequences, cursor-movement, or other terminal control sequences that get rendered raw to the victim's terminal when they run `gh repo read-dir --repo <attacker/repo>`.

### Finding Description
The call path is: `fetchTree` (pkg/cmd/repo/read-dir/http.go:129-221) queries GitHub's GraphQL API for `Tree.Entries`, and copies the untrusted `Name`/`NameRaw` fields verbatim into `dirEntry{Name: e.Name, ...}` [1](#0-0) . This flows to `readDirRun` → `writeTable` (only used on TTY, since non-TTY goes through `writeTSV` which is arguably safer as terminal-rendering is not expected there) [2](#0-1) . Inside `writeTable`, `e.Name` is passed straight to `tp.AddField(e.Name, tableprinter.WithColor(...))` with no sanitization step [3](#0-2) .

Git tree entry names are attacker-controlled: any GitHub user can create a public repo with a file whose name contains raw byte sequences (git blob/tree names are not strictly limited to printable ASCII, only NUL and `/` are disallowed by git), including ESC (`\x1b`) sequences for OSC 8 hyperlinks, cursor repositioning, or terminal title/clearing. This codebase already recognizes this exact class of risk and mitigates it elsewhere: `pkg/cmd/skills/list/list.go` defines `sanitizeForTerminal` which runs values through `asciisanitizer.Sanitizer` specifically "so frontmatter values cannot inject terminal escapes" [4](#0-3) , and applies it to untrusted `skillName`/`source` fields before `AddField` [5](#0-4) . The underlying `tableprinter.TablePrinter.AddField` (github.com/cli/go-gh/v2/pkg/tableprinter, wrapped by `internal/tableprinter/table_printer.go`) does not perform this sanitization itself — it is the caller's responsibility, and other renderers in this codebase (`pkg/cmd/discussion/list/list.go`, `pkg/cmd/search/shared/shared.go`) at most apply `text.RemoveExcessiveWhitespace`, which does not strip ANSI/control bytes. `writeTable` in read-dir has no equivalent sanitization call.

### Impact Explanation
When a victim with a TTY runs `gh repo read-dir --repo <attacker/repo>` against an attacker's public repository (or a fork/branch they point the victim at), file/directory names in that tree are rendered raw to the victim's terminal. This can be used to: hide or spoof entries (e.g., cursor movement to overwrite the display), forge fake prompts via OSC 8 hyperlinks or other escape trickery, or manipulate terminal state (title bar, screen clearing) — a terminal escape/prompt-injection class issue matching GitHub's "terminal escape sequence injection" bounty impact category. Impact is scoped to terminal rendering corruption/spoofing in the victim's session; it does not by itself achieve code execution or credential theft.

### Likelihood Explanation
Feasible and low-effort: the attacker only needs to publish a public repository (or a branch/ref reachable via `--ref`) containing a file whose name embeds control bytes, and get the victim to run `gh repo read-dir --repo <attacker/repo>` while attached to a TTY (the default rendering path, not requiring `--json` or piped output). Since `gh repo read-dir` is explicitly for browsing directories of arbitrary/unfamiliar repositories, victims running it against untrusted repos is a realistic and expected usage pattern for this command.

### Recommendation
Sanitize `e.Name` (and any other attacker-controlled field rendered to the TTY, e.g. entry type/size are safe/derived, but `Name` is not) in `writeTable` before calling `tp.AddField`, mirroring the existing `sanitizeForTerminal` helper pattern in `pkg/cmd/skills/list/list.go` (backed by `asciisanitizer.Sanitizer`). Apply the same sanitization to any other TTY-rendered surface of tree entry names in this command.

### Proof of Concept
```go
// pkg/cmd/repo/read-dir/read_dir_test.go (illustrative)
func TestWriteTable_SanitizesControlBytes(t *testing.T) {
    ios, _, out, _ := iostreams.Test()
    ios.SetStdoutTTY(true)
    ios.SetColorEnabled(false)

    dir := &repoDir{
        Entries: []dirEntry{
            {
                Name: "safe\x1b]8;;http://evil.example/\x07CLICK\x1b]8;;\x07", // OSC 8 hyperlink injection
                Type: "file",
                Size: 10,
            },
        },
    }

    err := writeTable(ios, dir)
    require.NoError(t, err)

    rendered := out.String()
    // Expected (fixed) behavior: no raw ESC (\x1b) or BEL (\x07) bytes reach output.
    require.NotContains(t, rendered, "\x1b")
    require.NotContains(t, rendered, "\x07")
}
```
Currently this test would fail because `writeTable` forwards `e.Name` unmodified into `tp.AddField`, allowing the raw ESC/OSC bytes to reach `out` [3](#0-2) .

### Citations

**File:** pkg/cmd/repo/read-dir/http.go (L198-209)
```go
	for _, e := range obj.Tree.Entries {
		entry := dirEntry{
			Name:    e.Name,
			Path:    e.Path,
			NameRaw: e.NameRaw,
			PathRaw: e.PathRaw,
			Type:    entryTypeFromMode(e.Mode),
			GitType: e.Type,
			Mode:    e.Mode,
			GitSHA:  e.OID,
			Size:    e.Size,
		}
```

**File:** pkg/cmd/repo/read-dir/read_dir.go (L130-149)
```go
	if !opts.IO.IsStdoutTTY() {
		return writeTSV(opts.IO, dir)
	}

	if err := opts.IO.StartPager(); err != nil {
		fmt.Fprintf(opts.IO.ErrOut, "error starting pager: %v\n", err)
	}
	defer opts.IO.StopPager()

	location := ghrepo.FullName(repo)
	if opts.Path != "" {
		location = fmt.Sprintf("%s/%s", location, strings.TrimPrefix(opts.Path, "/"))
	}
	noun := "entries"
	if len(dir.Entries) == 1 {
		noun = "entry"
	}
	fmt.Fprintf(opts.IO.Out, "Showing %d %s in %s\n\n", len(dir.Entries), noun, location)

	return writeTable(opts.IO, dir)
```

**File:** pkg/cmd/repo/read-dir/read_dir.go (L194-196)
```go
		tp.AddField(entryType)
		tp.AddField(e.Name, tableprinter.WithColor(cs.ColorFromString(color)))
		tp.AddField(size)
```

**File:** pkg/cmd/skills/list/list.go (L509-514)
```go
	for _, skill := range skills {
		table.AddField(sanitizeForTerminal(skill.skillName))
		table.AddField(formatAgentHosts(skill.agentHostIDs))
		table.AddField(displayOrDash(skill.scope))
		table.AddField(displayOrDash(sanitizeForTerminal(skill.source)))
		table.EndRow()
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
