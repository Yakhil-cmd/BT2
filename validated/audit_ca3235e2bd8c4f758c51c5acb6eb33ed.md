### Title
Skill file-tree rendering prints attacker-controlled file names without terminal-escape sanitization - (File: pkg/cmd/skills/preview/preview.go)

### Summary
`buildTree`/`printTree` in `pkg/cmd/skills/preview/preview.go` build and render a tree of skill file paths taken directly from `discovery.SkillFile.Path` values returned by the GitHub tree API for the attacker's published repository. Unlike the SKILL.md/extra-file *content*, which is fetched as sanitizing-on-print `Untrusted` values (`content.String()`), the file *names* used to build the tree are plain Go strings passed straight to `fmt.Fprintf` with no escape-sequence stripping.

### Finding Description
`renderFileTree` calls `buildTree(files)` then `printTree(w, cs, root.children, "")` [1](#0-0) . `buildTree` splits each `discovery.SkillFile.Path` on `/` and stores each path segment verbatim as `treeNode.name` [2](#0-1) . `printTree` then writes `node.name` directly with `fmt.Fprintf(w, "%s%s%s\n", indent, cs.Muted(connector), node.name)` for files and `cs.Bold(node.name+"/")` for directories [3](#0-2) , with no call to any sanitizer.

This is inconsistent with the rest of the codebase's handling of untrusted skill-sourced strings:
- Blob content fetched from the API is treated as `Untrusted` and its `String()` method neutralizes ANSI/OSC/CSI sequences automatically on any `fmt` print path [4](#0-3) .
- The sibling `gh skill list` command explicitly wraps other attacker-influenced display fields (skill name, source URL, derived from frontmatter) in `sanitizeForTerminal`, which runs them through the `asciisanitizer.Sanitizer` before printing to a table [5](#0-4) .

No equivalent wrapping exists for `SkillFile.Path` segments in `preview.go`'s tree renderer. Because `discovery.ListSkillFiles`/`DiscoverSkillFiles` derive `Path` from the Git tree entries of a repository the attacker fully controls (they can name files/directories with embedded C0/C1 control bytes, including OSC 8 hyperlink payloads, cursor-movement CSI sequences, or terminal-title/OSC 52 clipboard sequences), an attacker who publishes a malicious skill can inject raw escape sequences into every `gh skill preview` invocation against that repository — both the non-interactive pager path (`renderAllFiles` → `renderFileTree`) and the interactive path shown before the file picker (`renderInteractive` → `renderFileTree`, printed to stderr).

### Impact Explanation
This allows terminal output/prompt spoofing: a crafted file name can hide or rewrite lines already printed (e.g., masking a warning), move the cursor, set a bogus terminal title, or in vulnerable terminal emulators trigger clipboard writes (OSC 52) or other terminal-specific side effects, directly in the output of an ordinary `gh skill preview` run against attacker content. This matches the "Terminal output/prompt spoofing" bounty impact class cited in the question — the victim runs no privileged code, but the terminal display they trust to represent the repository's file layout can be falsified.

### Likelihood Explanation
Fully attacker-controlled and requires no special privileges: any user can publish a public repository/skill with maliciously named files, and any victim running `gh skill preview <attacker-repo> <skill>` (or letting the interactive skill browser list it) will have the payload rendered. It is deterministic and repeatable on every invocation, not race-dependent.

### Recommendation
Sanitize each path segment (and `skill.DisplayName()`, which is also printed raw via `cs.Bold(skill.DisplayName()+"/")`) with the same `asciisanitizer`-based mechanism already used in `pkg/cmd/skills/list/list.go` (`sanitizeForTerminal`) or by wrapping `SkillFile.Path` in `iostreams.NewUntrusted(...)` before it reaches `buildTree`/`printTree`, so file/directory names cannot carry raw control or escape sequences into terminal output.

### Proof of Concept
Add a golden test in `pkg/cmd/skills/preview/preview_test.go` that constructs `discovery.SkillFile` entries whose `Path` contains a CSI/OSC payload, e.g.:
```go
files := []discovery.SkillFile{
    {Path: "SKILL.md"},
    {Path: "scripts/\x1b]0;pwned\x07evil.sh"},
}
var buf bytes.Buffer
cs := iostreams.NewColorScheme(true, true, true)
renderFileTree(&buf, cs, files)
if strings.Contains(buf.String(), "\x1b]0;") {
    t.Fatalf("unsanitized OSC sequence reached terminal output: %q", buf.String())
}
```
Expected (post-fix) assertion: the OSC/CSI bytes are stripped or escaped before being written to `w`; currently the raw bytes pass through unchanged, demonstrating the vulnerability.

### Citations

**File:** pkg/cmd/skills/preview/preview.go (L495-498)
```go
func renderFileTree(w io.Writer, cs *iostreams.ColorScheme, files []discovery.SkillFile) {
	root := buildTree(files)
	printTree(w, cs, root.children, "")
}
```

**File:** pkg/cmd/skills/preview/preview.go (L501-525)
```go
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
