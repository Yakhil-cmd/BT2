### Title
Skill/file names from attacker-controlled repos are printed to the terminal without escape-sequence sanitization - (File: pkg/cmd/skills/preview/preview.go)

### Summary
`previewRun` renders `skill.DisplayName()` and raw file paths (`f.Path`) from an attacker-published repository directly to the terminal via `fmt.Fprintf`/`cs.Bold`, without passing them through the codebase's established terminal-sanitization mechanism. Both directory/tree names and `DisplayName()` come from git tree/blob entry names in the attacker's own repository, which can contain arbitrary bytes (including ANSI/C0 control sequences) since Git only forbids `/` and NUL in path components.

### Finding Description
`previewRun` (preview.go:279-283) prints `cs.Bold(skill.DisplayName()+"/")` [1](#0-0)  followed by `renderFileTree`, which walks `discovery.SkillFile.Path` components and writes `node.name` unsanitized into the terminal via `printTree` [2](#0-1) . The same pattern repeats for extra files: `cs.Bold("── "+f.Path+" ──")` at renderAllFiles and renderInteractive [3](#0-2) [4](#0-3) .

`skill.DisplayName()` and the tree/file paths originate from `discovery.DiscoverSkillsWithOptions`/`ListSkillFiles`, which enumerate the git tree of the attacker's repo at the resolved ref — fully attacker-controlled content, since the victim is instructed to run `gh skill preview <attacker-repo>`. Git tree entry names can contain arbitrary bytes other than `/` and NUL, so an attacker can name a directory or file with embedded ANSI escape sequences (e.g., cursor movement, screen-clear, terminal title, or OSC 52 clipboard-write sequences).

The codebase has an established, deliberate defense for exactly this class of issue: `pkg/iostreams/untrusted.go`'s `Untrusted` type auto-sanitizes ANSI/control sequences via `asciisanitizer.Sanitizer` on every `String()`/print call [5](#0-4) , and `pkg/cmd/skills/list/list.go` explicitly wraps skill names/sources with `sanitizeForTerminal` before writing them to a table for the same reason ("frontmatter values cannot inject terminal escapes") [6](#0-5) [7](#0-6) . `preview.go`, however, prints `skill.DisplayName()` and `f.Path` as plain Go strings directly through `fmt.Fprintf`, bypassing both the `Untrusted` wrapper and `sanitizeForTerminal`, so none of these existing protections apply to this code path.

### Impact Explanation
This enables terminal escape sequence injection (terminal spoofing/manipulation) against a victim who runs `gh skill preview <attacker-owner>/<attacker-repo>`. Depending on the victim's terminal emulator, this can manipulate the visible output (hide/replace lines, fake prompts), change the terminal title, or, on terminals that support OSC 52, write to the victim's clipboard. This falls under the "terminal escape sequence injection to manipulate or misrepresent output" bounty class rather than remote code execution, since Go's `fmt` writers do not execute shell/OS commands.

### Likelihood Explanation
High feasibility and repeatability: the attacker only needs to publish a public GitHub repository with a `SKILL.md` and a directory/file name containing control characters (fully within attacker's control, no victim interaction beyond running the documented command `gh skill preview <repo>`). No privileges, tokens, or MITM required — matches the described unprivileged remote attacker model exactly.

### Recommendation
Sanitize all repo-derived display strings before writing them to the terminal in `preview.go`, consistent with the existing `sanitizeForTerminal`/`iostreams.Untrusted` pattern used in `pkg/cmd/skills/list/list.go`:
- Wrap `skill.DisplayName()` with the sanitizer before use in `cs.Bold(...)` calls (lines 280, 323).
- Sanitize `f.Path`/`node.name` in `renderFileTree`/`printTree` and in the `"── "+f.Path+" ──"` headers (lines 303-309, 551-554).
- Alternatively, have `discovery.Skill.DisplayName()` and `discovery.SkillFile.Path` return/expose values as `iostreams.Untrusted` so `fmt` printing auto-sanitizes them, matching the safety guarantee documented in `untrusted.go`.

### Proof of Concept
Go test plan using `httpmock`/`git-stub` style fixtures for `discovery`:
1. Mock the GitHub tree/blob API responses (as consumed by `discovery.DiscoverSkillsWithOptions`/`ListSkillFiles`) to include a skill directory name containing an embedded ANSI escape, e.g. `"evil\x1b[31mSKILL"` and a file entry with a similar name.
2. Invoke `previewRun` with `IO` set to a `iostreams.Test()` fake with `CanPrompt()` false (to hit `renderAllFiles`), and capture `IO.Out`.
3. Assert that the captured output bytes contain the raw `0x1b` (ESC) byte instead of a sanitized/escaped representation — demonstrating the injected sequence passes through unmodified.
4. Compare against `pkg/cmd/skills/list/list.go`'s `renderTable`, and assert (as expected behavior after fix) that after sanitization the ESC byte is replaced/stripped, matching `sanitizeForTerminal`'s guarantee.

### Citations

**File:** pkg/cmd/skills/preview/preview.go (L279-283)
```go
	if len(files) > 0 {
		fmt.Fprintf(out, "%s\n", cs.Bold(skill.DisplayName()+"/"))
		renderFileTree(out, cs, files)
		fmt.Fprintln(out)
	}
```

**File:** pkg/cmd/skills/preview/preview.go (L303-309)
```go
			fmt.Fprintf(out, "\n%s\n\n%s\n", cs.Bold("── "+f.Path+" ──"), cs.Muted("(could not fetch file)"))
			continue
		}
		fetched++
		sanitized := fileContent.String()
		totalBytes += len(sanitized)
		fmt.Fprintf(out, "\n%s\n\n", cs.Bold("── "+f.Path+" ──"))
```

**File:** pkg/cmd/skills/preview/preview.go (L323-324)
```go
	fmt.Fprintf(opts.IO.ErrOut, "\n%s\n", cs.Bold(skill.DisplayName()+"/"))
	renderFileTree(opts.IO.ErrOut, cs, files)
```

**File:** pkg/cmd/skills/preview/preview.go (L541-556)
```go
func printTree(w io.Writer, cs *iostreams.ColorScheme, nodes []*treeNode, indent string) {
	for i, node := range nodes {
		isLast := i == len(nodes)-1
		connector := "├── "
		childIndent := "│   "
		if isLast {
			connector = "└── "
			childIndent = "    "
		}
		if node.isDir {
			fmt.Fprintf(w, "%s%s%s\n", indent, cs.Muted(connector), cs.Bold(node.name+"/"))
			printTree(w, cs, node.children, indent+cs.Muted(childIndent))
		} else {
			fmt.Fprintf(w, "%s%s%s\n", indent, cs.Muted(connector), node.name)
		}
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
