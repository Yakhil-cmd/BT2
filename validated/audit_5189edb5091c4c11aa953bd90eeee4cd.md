### Title
Skill file/directory names in the preview tree are printed unsanitized, enabling terminal escape/ANSI injection via `printTree` - (File: pkg/cmd/skills/preview/preview.go)

### Summary
`printTree` in `pkg/cmd/skills/preview/preview.go` (line 541) writes `node.name` directly into the output stream with `fmt.Fprintf` without any control-character or ANSI-escape sanitization. Since `node.name` originates from file/directory entry names discovered in an attacker-published repository's skill tree (`discovery.SkillFile.Path`), a malicious skill author can embed terminal escape sequences in a file or directory name that get rendered raw in the victim's terminal or pager.

### Finding Description
The call chain is: `renderFileTree` (preview.go:495) → `buildTree` (preview.go:501) → `printTree` (preview.go:541). `buildTree` splits `discovery.SkillFile.Path` on `/` and stores each path segment verbatim as `treeNode.name` (preview.go:504-521), with no validation beyond structural path splitting. `discovery.SkillFile.Path` values are populated from git tree entries returned by the GitHub API for the target repository/ref, which is fully attacker-controlled (the attacker publishes the repo, its file tree, and file names).

`printTree` then emits these names directly:
```go
fmt.Fprintf(w, "%s%s%s\n", indent, cs.Muted(connector), cs.Bold(node.name+"/"))
...
fmt.Fprintf(w, "%s%s%s\n", indent, cs.Muted(connector), node.name)
``` [1](#0-0) 

There is no call to any sanitization routine (e.g., stripping ANSI/CSI sequences, control characters, or carriage returns) on `node.name` before it is written. I found sanitization/escaping helpers referenced in many other `gh` view/list commands, but no equivalent safeguard is applied in the skills preview tree renderer path (`buildTree`/`printTree`), and `discovery.SkillFile`'s only name constraints I could find (`safeNamePattern`, `specNamePattern` in `internal/skills/discovery/discovery.go`) are used for skill *name* matching, not for filtering raw tree entry path segments used purely for display purposes. [2](#0-1) 

Because the command's documented behavior is to "display it using the configured pager" and to browse skill files interactively, the tree output (and other rendered content) is plausibly piped through an external pager/renderer whose escape-sequence handling may differ from `gh`'s own terminal-safe rendering assumptions. A crafted file/directory name containing raw ANSI escape sequences (e.g., cursor movement, screen-clear, OSC sequences that rewrite the terminal title, or sequences some terminals interpret as clipboard/URL/hyperlink injection) would be echoed unmodified into that pager, producing spoofed or misleading terminal output.

### Impact Explanation
This enables terminal output spoofing: a malicious skill's file/directory names can inject ANSI/control sequences to hide, alter, or fake lines in the previewed tree (e.g., making a malicious script appear benign, or hiding parts of the tree from the user), which can be used to social-engineer the user into confirming a destructive action or trusting the wrong file. This matches the "Terminal output/prompt spoofing" bounty impact class described in the question. Actual code execution is unlikely since gh does not `exec` the pager with attacker data as arguments — the risk is confined to display-only escape sequence injection.

### Likelihood Explanation
Precondition is simply that the attacker publishes a repository containing a skill whose file tree includes crafted file or directory names, and the victim runs `gh skills preview <attacker-repo>`. This requires no special privileges beyond being able to publish public repository content, matching the specified unprivileged-attacker threat model. The exploit is fully repeatable and does not depend on races or timing.

### Recommendation
Sanitize `node.name` (and any other attacker-controlled path/frontmatter/registry-metadata strings rendered to the terminal) before writing, e.g. strip or escape ANSI CSI/OSC sequences and non-printable control characters, consistent with sanitization already applied elsewhere in `gh` for remote text rendered to terminal. Apply this sanitization at the point path segments are captured in `buildTree`, not just at output time, so all consumers of `treeNode.name` are protected.

### Proof of Concept
```go
func TestPrintTree_SanitizesEscapeSequences(t *testing.T) {
	cs := iostreams.NewColorScheme(true, true, true)
	malicious := []discovery.SkillFile{
		{Path: "safe.txt"},
		{Path: "\x1b[2J\x1b[H\x1b]0;pwned\x07evil.sh"},
	}
	root := buildTree(malicious)
	var buf bytes.Buffer
	printTree(&buf, cs, root.children, "")

	out := buf.String()
	if strings.ContainsAny(out, "\x1b\x07") {
		t.Fatalf("expected sanitized output, got raw escape sequences: %q", out)
	}
}
```
Expected (failing) result on current code: the test fails because `printTree` writes the raw `\x1b[2J\x1b[H\x1b]0;pwned\x07` bytes verbatim into the tree output, demonstrating that unsanitized escape sequences from an attacker-controlled file name reach the writer that feeds the pager/terminal.

### Citations

**File:** pkg/cmd/skills/preview/preview.go (L541-557)
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
}
```

**File:** internal/skills/discovery/discovery.go (L24-42)
```go
// specNamePattern matches the strict agentskills.io name spec:
// 1-64 chars, lowercase alphanumeric + hyphens, no leading/trailing/consecutive hyphens.
var specNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// TreeTooLargeError is returned when a repository's git tree exceeds the
// GitHub API truncation limit and full skill discovery is not possible.
type TreeTooLargeError struct {
	Owner string
	Repo  string
}

func (e *TreeTooLargeError) Error() string {
	return fmt.Sprintf("repository tree for %s/%s is too large for full discovery", e.Owner, e.Repo)
}

// safeNamePattern matches names that are safe for filesystem use during discovery.
// Allows letters (any case), numbers, hyphens, underscores, dots, and spaces.
// Must start with a letter or number. This matches copilot-agent-runtime's SKILL_NAME_REGEX.
var safeNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._\- ]*$`)
```
