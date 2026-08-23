### Title
Unsanitized file names printed to terminal in `printTree` allow ANSI/OSC escape injection - (File: pkg/cmd/skills/preview/preview.go)

### Summary
`printTree` in `pkg/cmd/skills/preview/preview.go` writes `treeNode.name` values — derived directly from a published skill's repository tree entry paths (`discovery.SkillFile.Path`) — to the terminal via `fmt.Fprintf` with no escape-sequence or control-character sanitization. Because these paths are fully attacker-controlled (any file/directory name in a repo the attacker publishes), a malicious skill repository can embed ANSI/OSC/DCS sequences in a file name that get rendered verbatim to the victim's terminal when they run `gh skills preview`.

### Finding Description
`renderFileTree` builds a tree from `discovery.SkillFile` entries obtained via `discovery.ListSkillFiles` (the git tree API for the skill's directory) [1](#0-0) , and `buildTree` splits `f.Path` (attacker-controlled repo file paths) into `treeNode.name` fields with no sanitization [2](#0-1) . `printTree` then writes those names straight to the destination writer:

```go
fmt.Fprintf(w, "%s%s%s\n", indent, cs.Muted(connector), cs.Bold(node.name+"/"))
...
fmt.Fprintf(w, "%s%s%s\n", indent, cs.Muted(connector), node.name)
``` [3](#0-2) 

This is called from two paths:
- `renderAllFiles`, writing to `opts.IO.Out` inside the pager [4](#0-3) .
- `renderInteractive`, writing directly to `opts.IO.ErrOut` **before any pager is started**, so it hits the terminal immediately, unbuffered and unsanitized [5](#0-4) .

Neither `opts.IO.Out` nor `opts.IO.ErrOut` passes through the `asciisanitizer` transform — only `IO.ContentOut` does that, and only when `SetContentSanitization` keeps it enabled [6](#0-5) . `printTree` never routes through `ContentOut`, `iostreams.Untrusted`, or any equivalent of the `sanitizeForTerminal` helper that `pkg/cmd/skills/list/list.go` deliberately applies to frontmatter-derived, attacker-controlled strings before printing them in `renderTable` [7](#0-6) . That sibling command demonstrates the project's own established mitigation pattern for this exact class of input (skill metadata strings reaching the terminal), which `preview.go`'s file-tree renderer omits entirely.

The rendered `SKILL.md` body and extra file contents in this same command are also passed through `markdown.Render`/pager machinery, but the raw tree file names bypass that path completely, so a file named e.g. `\x1b]52;c;<base64>\x07legit.txt` or containing an OSC 7/title-set/DCS sequence in an archive entry would have its control bytes emitted verbatim to the victim's terminal.

### Impact Explanation
An attacker who publishes a skill repository (fully within the unprivileged remote-attacker capability of publishing repos/skills) can plant a file with escape-sequence-laden names in the skill directory. When a victim runs `gh skills preview <attacker-repo>`, `printTree` prints that name unsanitized to the terminal (stdout via pager, or stderr immediately in interactive mode). This enables classic terminal-injection attacks: OSC 52 clipboard write, terminal title/window manipulation, cursor-position tricks to spoof subsequent prompt text, or (on vulnerable terminal emulators) more severe sequences — matching the "Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation" impact class.

### Likelihood Explanation
Highly feasible and repeatable: creating a file with an escape-sequence-bearing name in a git repository requires no special privileges — just publishing a public repo/skill and having a victim invoke `gh skills preview <repo>` on it (or select it interactively via `gh skills preview <repo>`), which is the documented normal use of the command. No host, MITM, or token requirements are needed.

### Recommendation
Sanitize `node.name` (and any other repository-tree-derived text rendered via `printTree`/`renderFileTree`) before writing to the terminal, e.g. by running it through the same `asciisanitizer`-based helper (`sanitizeForTerminal`) already used in `pkg/cmd/skills/list/list.go`, or by wrapping the values in `iostreams.NewUntrusted(...)` before formatting so the `%s`/`Fprintf` calls automatically strip C0/C1 control and ANSI/OSC sequences.

### Proof of Concept
```go
// pkg/cmd/skills/preview/preview_test.go
func TestPrintTree_SanitizesEscapeSequences(t *testing.T) {
    ios, _, out, _ := iostreams.Test()
    cs := ios.ColorScheme()

    files := []discovery.SkillFile{
        {Path: "safe.txt"},
        {Path: "evil\x1b]0;HIJACKED\x07.txt"},
    }
    root := buildTree(files)
    printTree(out, cs, root.children, "")

    got := out.String()
    require.NotContains(t, got, "\x1b", "raw ESC byte must not reach the terminal, got: %q", got)
}
```
Expected today: the assertion fails because the raw `\x1b` byte from the crafted file name is present in `out.String()`, confirming the unsanitized passthrough.

### Citations

**File:** pkg/cmd/skills/preview/preview.go (L197-205)
```go
	opts.IO.StartProgressIndicatorWithLabel("Fetching skill content")
	var files []discovery.SkillFile
	if skill.TreeSHA != "" {
		files, err = discovery.ListSkillFiles(apiClient, hostname, owner, repoName, skill.TreeSHA)
		if err != nil {
			fmt.Fprintf(opts.IO.ErrOut, "warning: could not list skill files: %v\n", err)
			files = nil
		}
	}
```

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

**File:** pkg/iostreams/iostreams.go (L490-508)
```go
// SetContentSanitization toggles ANSI escape sanitization on ContentOut.
// Commands should call this with false when an explicit opt-out flag (e.g.
// --allow-escape-sequences) is set, so subsequent writes of external content
// pass through unmodified.
func (s *IOStreams) SetContentSanitization(enabled bool) {
	s.sanitizeContent = enabled
	s.ContentOut = newContentWriter(s.Out, enabled)
}

// newContentWriter returns the writer to wire up as ContentOut. When
// sanitize is true it inserts an asciisanitizer in front of the underlying
// writer; otherwise it returns the underlying writer directly so writes
// reach stdout unchanged.
func newContentWriter(out io.Writer, sanitize bool) io.Writer {
	if !sanitize {
		return out
	}
	return transform.NewWriter(out, &asciisanitizer.Sanitizer{})
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
