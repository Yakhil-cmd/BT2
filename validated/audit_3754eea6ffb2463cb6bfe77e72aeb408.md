## Finding [1](#0-0) 

`printTree` writes `node.name` — derived directly from `discovery.SkillFile.Path` — into the terminal writer via `fmt.Fprintf` with no sanitization, unlike the parallel `skills list` command which explicitly wraps untrusted frontmatter-derived strings (`skillName`, `source`) with `sanitizeForTerminal` using `asciisanitizer.Sanitizer` before printing to a table. [2](#0-1) 

The codebase already has an established pattern (`pkg/iostreams/untrusted.go`'s `Untrusted` type, and `list.go`'s `sanitizeForTerminal`) for exactly this class of risk: any string obtained from a remote repository (blob content, frontmatter fields, file/tree paths) is untrusted and must be sanitized before reaching a terminal writer. [3](#0-2) 

In `preview.go`, `buildTree` splits `f.Path` (attacker-controlled — sourced from the git tree listing of a repo the attacker publishes) into path segments and stores them verbatim as `treeNode.name`. [4](#0-3) 

`renderFileTree` is called from both the non-interactive path (`renderAllFiles`, writing to the paged `opts.IO.Out`) and the interactive path (`renderInteractive`, writing directly to `opts.IO.ErrOut`, which is *not* wrapped by the pager and is written immediately to the terminal). [5](#0-4) [6](#0-5) 

Neither call path sanitizes `f.Path`/`node.name` before it reaches `fmt.Fprintf`. Since `SkillFile.Path` values come straight from the GitHub tree API response for a repository fully controlled by the attacker, an attacker can place a file at a path whose segment contains raw ESC (0x1B) bytes, e.g. `scripts/\x1b]0;pwned\x07evil.sh`, and that byte sequence flows unmodified through `discovery.ListSkillFiles` → `buildTree` → `printTree` → `fmt.Fprintf(w, ...)` straight to the victim's terminal.

### Title
Terminal control-sequence injection via unsanitized file path in skill file tree rendering - (File: pkg/cmd/skills/preview/preview.go)

### Summary
`gh skill preview` renders a file tree of the skill's repository contents using raw file/directory path segments obtained from the GitHub tree API, without stripping ANSI/OSC control sequences. A malicious repo can embed a path segment such as `\x1b]0;pwned\x07` or `\x1b[8m` in a non-`SKILL.md` file, and the raw escape bytes are printed to the victim's terminal when the tree is displayed, purely by running `gh skill preview <attacker-repo>`.

### Finding Description
`previewRun` fetches skill files via `discovery.ListSkillFiles` (populating `discovery.SkillFile.Path` from the GitHub tree API for a repo the attacker fully controls), then calls `renderAllFiles`/`renderInteractive`, which call `renderFileTree` → `buildTree`/`printTree`. `buildTree` splits `f.Path` on `/` and stores each segment unchanged as `treeNode.name`; `printTree` then writes it with `fmt.Fprintf(w, "%s%s%s\n", indent, cs.Muted(connector), node.name)` (and similarly for directories). No sanitization step exists on this path. This is in contrast to the sibling `skills list` command, which explicitly passes untrusted, repo-derived strings through `sanitizeForTerminal`/`asciisanitizer.Sanitizer` before printing, and the codebase's dedicated `iostreams.Untrusted` wrapper type built for this exact purpose. Because path segments come from a git tree listing that the attacker fully controls (any byte sequence except `/` and NUL is a valid tree entry name), the attacker can smuggle raw ESC (`0x1B`) sequences into the terminal output stream.

### Impact Explanation
This allows terminal control-sequence injection (OSC title spoofing, SGR sequences to hide/alter displayed text, cursor repositioning) triggered simply by running `gh skill preview` against an attacker-published, uninstalled repository — matching GitHub's "terminal escape sequence / output injection" impact class for the CLI. Impact is limited to terminal manipulation/spoofing (no code execution or credential exfiltration is directly achieved by this primitive alone).

### Likelihood Explanation
Fully attacker-controlled and requires no victim action beyond running `gh skill preview <repo>` on a skill with any extra file (very common, since most published skills include `scripts/` or `references/` directories) in either interactive or non-interactive mode. No special permissions or victim installation step needed.

### Recommendation
Sanitize `SkillFile.Path` (or `node.name` at render time) with `asciisanitizer.Sanitizer` / the existing `sanitizeForTerminal` helper (or wrap with `iostreams.Untrusted`) before it is written by `printTree`, consistent with how `pkg/cmd/skills/list/list.go` handles untrusted, repo-derived strings.

### Proof of Concept
```go
func TestRenderFileTree_SanitizesControlBytes(t *testing.T) {
    files := []discovery.SkillFile{
        {Path: "SKILL.md"},
        {Path: "scripts/\x1b]0;pwned\x07evil.sh"},
    }
    var buf bytes.Buffer
    io, _, _, _ := iostreams.Test()
    cs := io.ColorScheme()
    renderFileTree(&buf, cs, files)
    if bytes.ContainsRune(buf.Bytes(), 0x1B) {
        t.Fatalf("raw ESC byte reached terminal output: %q", buf.String())
    }
}
```
Expected today: the assertion fails because `buf` contains the raw `0x1B` byte, confirming the injection reaches the writer unsanitized.

### Citations

**File:** pkg/cmd/skills/preview/preview.go (L279-283)
```go
	if len(files) > 0 {
		fmt.Fprintf(out, "%s\n", cs.Bold(skill.DisplayName()+"/"))
		renderFileTree(out, cs, files)
		fmt.Fprintln(out)
	}
```

**File:** pkg/cmd/skills/preview/preview.go (L322-325)
```go
	// Show the file tree to stderr so it persists above the prompt
	fmt.Fprintf(opts.IO.ErrOut, "\n%s\n", cs.Bold(skill.DisplayName()+"/"))
	renderFileTree(opts.IO.ErrOut, cs, files)
	fmt.Fprintln(opts.IO.ErrOut)
```

**File:** pkg/cmd/skills/preview/preview.go (L500-525)
```go
// buildTree constructs a tree structure from flat file paths.
func buildTree(files []discovery.SkillFile) *treeNode {
	root := &treeNode{isDir: true}
	for _, f := range files {
		parts := strings.Split(f.Path, "/")
		current := root
		for i, part := range parts {
			isLast := i == len(parts)-1
			found := false
			for _, child := range current.children {
				if child.name == part {
					current = child
					found = true
					break
				}
			}
			if !found {
				node := &treeNode{name: part, isDir: !isLast}
				current.children = append(current.children, node)
				current = node
			}
		}
	}
	sortTree(root)
	return root
}
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

**File:** pkg/cmd/skills/list/list.go (L506-529)
```go
func renderTable(io *iostreams.IOStreams, skills []listedSkill) error {
	table := tableprinter.New(io, tableprinter.WithHeader("Name", "Agent", "Scope", "Source"))

	for _, skill := range skills {
		table.AddField(sanitizeForTerminal(skill.skillName))
		table.AddField(formatAgentHosts(skill.agentHostIDs))
		table.AddField(displayOrDash(skill.scope))
		table.AddField(displayOrDash(sanitizeForTerminal(skill.source)))
		table.EndRow()
	}

	return table.Render()
}

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
