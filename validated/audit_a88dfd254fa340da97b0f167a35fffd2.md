### Title
Unsanitized attacker-controlled tree entry names written to stdout in `writeTSV` enable terminal escape sequence injection - (File: pkg/cmd/repo/read-dir/read_dir.go)

### Summary
`writeTSV` in `pkg/cmd/repo/read-dir/read_dir.go` writes the GraphQL-derived `dirEntry.Name` field directly into `io.Out` via `fmt.Fprintf` without passing it through the codebase's `Untrusted` sanitization wrapper, even though entry names originate from attacker-controlled repository tree/file names. This lets a repo/fork owner embed ANSI/terminal escape sequences in a file or directory name that gh will forward verbatim to any consumer of its output (pager, `less`, terminal multiplexer, or a later `cat`/script that echoes the captured TSV).

### Finding Description
`fetchTree` in `pkg/cmd/repo/read-dir/http.go` populates `dirEntry.Name` straight from the GraphQL `Tree.Entries[].Name` field of an arbitrary repository/ref that the victim points `gh repo read-dir` at: [1](#0-0) 

That field is a plain `string`, not the `iostreams.Untrusted` type the codebase specifically introduced to neutralize ANSI escapes in remote content before it reaches a terminal-bound writer: [2](#0-1) [3](#0-2) 

`writeTSV` then writes `e.Name` unmodified into `io.Out`: [4](#0-3) 

Nothing in the intervening path (`fetchTree`, `readDirRun`) strips control characters or routes `Name` through `Untrusted.String()`/`stripControl`. A repository owner (or fork/PR author, since `--repo`/`--ref` are attacker-namespace-controllable by the invoking user pointing gh at attacker content) can create a file or directory whose git-tree name contains raw ESC (`0x1b`) bytes forming CSI/OSC sequences (e.g. cursor movement, screen clear, OSC 8 hyperlink spoofing, or terminal title manipulation). Since git tree entry names are largely unconstrained byte sequences (aside from `/` and NUL), this is directly attacker-controlled input reaching the sink unsanitized.

### Impact Explanation
Because `writeTSV` is used whenever stdout is not a TTY, the raw escape-laden bytes are what get piped to any downstream consumer — `less -R`, a custom pager, a script that stores and later displays the output, or a terminal multiplexer capturing the stream. This matches the "Terminal output/prompt spoofing" impact class: a malicious file/dir name can rewrite what the victim sees (e.g., spoof a different filename, hide entries, forge a confirmation prompt, or manipulate terminal title/state), which can be leveraged to trick a victim into taking a destructive or credential-disclosing action they did not intend.

### Likelihood Explanation
Preconditions are minimal and fully within an unprivileged attacker's control: publish a public repo (or a fork/PR branch) containing a file/directory whose name embeds ANSI escape sequences, then have the victim run `gh repo read-dir --repo attacker/repo` (or on a fork/ref they were directed to) with output redirected/piped (the common non-TTY case, e.g., in CI logs, scripts, or `| less`). No special git permissions are required to create tree entries with arbitrary byte names in a repository the attacker controls.

### Recommendation
Wrap `dirEntry.Name` (and any other remote-derived text emitted by `read-dir`, including in `writeTable`) in `iostreams.NewUntrusted(...)` and print via its sanitizing `String()`/`Fprint` path instead of writing the raw string directly, consistent with the pattern already established in `pkg/iostreams/untrusted.go` for other untrusted remote content. Apply the same treatment to `writeTable`'s `tp.AddField(e.Name, ...)` call, since it has the identical gap.

### Proof of Concept
```go
// pkg/cmd/repo/read-dir/read_dir_test.go (new test)
func TestWriteTSV_SanitizesEscapeSequences(t *testing.T) {
    ios, _, out, _ := iostreams.Test()
    dir := &repoDir{
        Entries: []dirEntry{
            {
                Type: "file",
                Name: "innocuous\x1b]0;pwned\x07.txt", // OSC title-set escape embedded in tree entry name
                Mode: 0o100644,
                Size: 10,
            },
        },
    }

    err := writeTSV(ios, dir)
    require.NoError(t, err)

    // Expected: no raw ESC (0x1b) byte should reach stdout.
    require.NotContains(t, out.String(), "\x1b",
        "writeTSV must sanitize attacker-controlled entry names before writing to Out")
}
```
Running this test against the current implementation fails: `out.String()` contains the raw `\x1b]0;pwned\x07` sequence, confirming the unsanitized escape bytes reach the writer that a pager/terminal consumes.

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

**File:** pkg/iostreams/untrusted.go (L11-23)
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
type Untrusted struct {
	raw string
}
```

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

**File:** pkg/cmd/repo/read-dir/read_dir.go (L152-161)
```go
// writeTSV writes a tab-separated listing for non-TTY output: type, name,
// octal mode, and raw byte size, with no header.
func writeTSV(io *iostreams.IOStreams, dir *repoDir) error {
	var sb strings.Builder
	for _, e := range dir.Entries {
		fmt.Fprintf(&sb, "%s\t%s\t%s\t%d\n", e.Type, e.Name, e.modeOctal(), e.Size)
	}
	_, err := io.Out.Write([]byte(sb.String()))
	return err
}
```
