### Title
Unsanitized check name/description/workflow strings can inject terminal escape sequences via `addRow` - (File: pkg/cmd/pr/checks/output.go)

### Summary
`addRow` in `pkg/cmd/pr/checks/output.go` writes `check.Name`, `check.Description`, `check.Workflow`, `check.Event`, and `check.Link` straight into the table printer with `tp.AddField(...)` and no escape-sequence sanitization. These fields originate from GitHub API check-run/commit-status data (check name, description, workflow name, event) that an attacker fully controls by opening a PR from a fork and running their own GitHub Actions workflow, so ANSI/OSC control sequences embedded in those values reach the victim's terminal unfiltered when they run `gh pr checks`.

### Finding Description
`addRow` receives a `check` value built by `aggregateChecks` in `pkg/cmd/pr/checks/aggregate.go`, which copies `Name`, `Description`, `Link`, `Event`, and `Workflow` directly from `api.CheckContext` (itself populated from the GitHub GraphQL/REST check-run and commit-status API) as plain `string` fields — not the `iostreams.Untrusted` wrapper type used elsewhere in the codebase for exactly this purpose: [1](#0-0) 

`addRow` then calls `tp.AddField(name)`, `tp.AddField(o.Description)`, `tp.AddField(o.Link)`, etc., with no call to any sanitizer: [2](#0-1) 

Contrast this with `pkg/cmd/skills/list/list.go`, where the same class of attacker-controlled, externally-authored string (a skill name/source parsed from repository frontmatter) is explicitly passed through `sanitizeForTerminal`, which strips ASCII control characters using `asciisanitizer.Sanitizer` before it reaches `table.AddField`: [3](#0-2) [4](#0-3) 

The codebase also has a dedicated `iostreams.Untrusted` type built for wrapping "content the application did not author" (HTTP response bodies, external file content) so that any `fmt` print path automatically neutralizes escape sequences via the asciisanitizer transform: [5](#0-4) 

Check names, descriptions, and workflow names are exactly this kind of externally-authored content — they are set by whatever CI system/GitHub Action created the check run or commit status, and an attacker opening a PR from a fork controls the workflow file that creates these check runs/statuses on their own fork's commit, which is what `gh pr checks` will display for that PR. Because `check.Name`, `check.Description`, `check.Workflow`, and `check.Event` remain plain `string` (not `Untrusted`) and `addRow` never routes them through `asciisanitizer`/`sanitizeForTerminal`, any ANSI/OSC/CSI byte sequences included in these attacker-supplied fields are written verbatim to the victim's terminal when they run `gh pr checks` on the attacker's PR.

### Impact Explanation
An attacker-controlled check name/description/workflow string containing terminal control sequences (e.g., switch to alternate screen buffer, disable local echo, enable mouse reporting, or an OSC title-set/query sequence) is emitted verbatim to the victim's TTY. Depending on the victim's terminal emulator, such sequences can alter terminal state in ways that persist after `gh` exits (e.g., leaving the terminal in alternate-screen mode or with echo disabled), enabling terminal/prompt spoofing that could facilitate credential capture or trick the user into confirming a destructive action in a subsequent, seemingly-normal-looking prompt. This matches the "High — Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation" impact class.

### Likelihood Explanation
No special privileges are required beyond opening a pull request from a fork the attacker controls, where the attacker also controls a workflow that creates a check run or commit status with a crafted `name`/`description` (or workflow `name`, which becomes `check.Workflow`). The victim only needs to run the ordinary `gh pr checks` command against that PR. This is straightforward and repeatable — the attacker fully controls the content of the injected fields.

### Recommendation
Sanitize `Name`, `Description`, `Workflow`, `Event`, and `Link` before they reach `tp.AddField` in `addRow`, consistent with the pattern already established in `pkg/cmd/skills/list/list.go` and `pkg/iostreams/untrusted.go`: either type these `check` fields as `iostreams.Untrusted` and call `.String()` when adding them as fields, or pass each value through `asciisanitizer.Sanitizer` (equivalent to `sanitizeForTerminal`) before calling `tp.AddField`.

### Proof of Concept
```go
package checks

import (
	"bytes"
	"testing"

	"github.com/cli/cli/v2/internal/tableprinter"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/stretchr/testify/assert"
)

func TestAddRow_DoesNotLeakEscapeSequences(t *testing.T) {
	ios, _, out, _ := iostreams.Test()
	ios.SetStdoutTTY(true)

	tp := tableprinter.New(ios, tableprinter.WithHeader("", "NAME", "DESCRIPTION", "ELAPSED", "URL"))

	malicious := check{
		Name:        "build",
		Workflow:    "evil\x1b]0;HIJACKED\x07",
		Description: "\x1b[?1049h", // switch to alternate screen buffer
		Bucket:      "fail",
		Link:        "https://example.com",
	}

	addRow(tp, ios, malicious)
	require := tp.Render()
	_ = require

	assert.NotContains(t, out.String(), "\x1b",
		"terminal escape sequences from check fields must not reach stdout, got: %q", out.String())
	_ = bytes.NewBuffer(nil)
}
```
Expected today: the test fails because `out.String()` contains the raw `\x1b` bytes, since `addRow` passes `Workflow`/`Description`/`Name` unsanitized to `tp.AddField`. After applying the recommended fix (routing these fields through `asciisanitizer`/`Untrusted`), the assertion should pass.

### Citations

**File:** pkg/cmd/pr/checks/aggregate.go (L12-22)
```go
type check struct {
	Name        string    `json:"name"`
	State       string    `json:"state"`
	StartedAt   time.Time `json:"startedAt"`
	CompletedAt time.Time `json:"completedAt"`
	Link        string    `json:"link"`
	Bucket      string    `json:"bucket"`
	Event       string    `json:"event"`
	Workflow    string    `json:"workflow"`
	Description string    `json:"description"`
}
```

**File:** pkg/cmd/pr/checks/output.go (L36-64)
```go
	if io.IsStdoutTTY() {
		var name string
		if o.Workflow != "" {
			name += fmt.Sprintf("%s/", o.Workflow)
		}
		name += o.Name
		if o.Event != "" {
			name += fmt.Sprintf(" (%s)", o.Event)
		}
		tp.AddField(mark, tableprinter.WithColor(markColor))
		tp.AddField(name)
		tp.AddField(o.Description)
		tp.AddField(elapsed)
		tp.AddField(o.Link)
	} else {
		tp.AddField(o.Name)
		if o.Bucket == "cancel" {
			tp.AddField("fail")
		} else {
			tp.AddField(o.Bucket)
		}
		if elapsed == "" {
			tp.AddField("0")
		} else {
			tp.AddField(elapsed)
		}
		tp.AddField(o.Link)
		tp.AddField(o.Description)
	}
```

**File:** pkg/cmd/skills/list/list.go (L506-518)
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

**File:** pkg/iostreams/untrusted.go (L11-44)
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

// NewUntrusted labels a string as untrusted external content.
func NewUntrusted(s string) Untrusted {
	return Untrusted{raw: s}
}

// NewUntrustedBytes labels a byte slice as untrusted external content.
func NewUntrustedBytes(b []byte) Untrusted {
	return Untrusted{raw: string(b)}
}

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
