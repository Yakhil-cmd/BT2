### Title
Unsanitized attacker-controlled comment author/body allows terminal escape sequence injection - ([File: pkg/cmd/pr/shared/comments.go])

### Finding Description
`api.Comment.AuthorLogin()`, `Association()`, `Content()`, `HiddenReason()`, and `Link()` return plain `string` values sourced directly from the GitHub API (comment author login/displayName, comment body, review state), which are attacker-controlled by anyone who can comment on an accessible issue/PR. In `pkg/cmd/pr/shared/comments.go`, `formatComment` (used by `CommentList`, reached from `viewRun` in `pkg/cmd/issue/view/view.go` line 342) and `formatRawComment` (used by `RawCommentList`, reached from `viewRun` line 190) write these fields with `fmt.Fprintf`/`fmt.Fprint` directly into a `strings.Builder`, which is then printed unmodified to `opts.IO.Out`: [1](#0-0) [2](#0-1) 

The comment body does pass through `markdown.Render` in `formatComment` before being written, but the author login, association, and hidden-reason fields are never sanitized, and `RawCommentList`/`formatRawComment` don't render markdown at all — the raw body (`comment.Content()`) is written verbatim via `fmt.Fprintln(&b, comment.Content())`, with no escaping step: [3](#0-2) 

The repository already contains a purpose-built mitigation for exactly this class of bug: `iostreams.Untrusted`, whose `String()` method runs content through `asciisanitizer.Sanitizer` (falling back to `stripControl`) to neutralize ANSI/OSC/control-sequence injection before it reaches a terminal writer: [4](#0-3) 

This wrapper is used elsewhere for untrusted remote content (e.g. `pkg/cmd/gist/view/view.go`, `internal/skills/discovery/discovery.go`, `pkg/cmd/agent-task/shared/log.go`), demonstrating the project's own threat model treats API-sourced text as needing sanitization before terminal output. However, the `Comment` interface and `pkg/cmd/pr/shared/comments.go` render path never wrap `AuthorLogin()`, `Association()`, `HiddenReason()`, or the raw `Content()` (in the `-c`/raw path) in `Untrusted`, so OSC/CSI/BEL sequences embedded in a comment author's display name or comment body are written unescaped to `opts.IO.Out`.

### Impact Explanation
An attacker who can comment on any issue/PR the victim views can embed terminal control sequences (e.g., OSC 52 clipboard-set, OSC 0/2 window-title rename, cursor-repositioning/overwrite tricks) that execute when the victim runs `gh issue view <n> -c` (or without `-c`, for the truncated preview, since `formatComment`'s header line also prints `AuthorLogin()` unsanitized). This can be used to spoof subsequent terminal output, rename the terminal title deceptively, or exfiltrate/overwrite the victim's clipboard via OSC52 — matching GitHub's "terminal escape sequence / injection leading to output spoofing or clipboard manipulation" impact class. It does not achieve code execution but is a real, low-friction terminal injection vector against ordinary `gh issue view`/`gh pr view` usage.

### Likelihood Explanation
Fully attacker-reachable with no special privileges: any GitHub user who can post a comment (or set a display name / login containing control bytes, where allowed by GitHub) on a public/accessible issue triggers this the moment the victim runs `gh issue view -c` (or default view for the truncated preview). No token, MITM, or social engineering needed beyond the victim viewing the issue, which is normal CLI usage.

### Recommendation
Sanitize all untrusted comment fields before they reach `opts.IO.Out`:
- Wrap `AuthorLogin()`, `Association()`, `HiddenReason()`, and `Content()` (for the raw/`-c` path in `formatRawComment`) with `iostreams.NewUntrusted(...)` (or an equivalent ANSI-sanitizing pass) before formatting, consistent with the existing pattern used in `pkg/cmd/gist/view/view.go` and `internal/skills/discovery/discovery.go`.
- For `formatComment`, ensure the markdown renderer's output for `Content()` is also passed through the sanitizer as a final terminal-output safety net, since markdown rendering itself is not designed to strip raw ANSI/OSC sequences embedded in source text.
- Apply the same wrapping to `formatHiddenComment` and any other place `Comment` interface fields are printed to a terminal writer.

### Proof of Concept
```go
package shared

import (
	"strings"
	"testing"

	"github.com/cli/cli/v2/api"
	"github.com/cli/cli/v2/pkg/iostreams"
)

func TestRawCommentList_SanitizesEscapeSequences(t *testing.T) {
	maliciousLogin := "attacker\x1b]0;PWNED\x07"
	maliciousBody := "hello\x1b]52;c;ZXZpbCBjbGlwYm9hcmQ=\x07world"

	comments := api.Comments{
		Nodes: []api.Comment{
			{
				Author: api.CommentAuthor{Login: maliciousLogin},
				Body:   maliciousBody,
			},
		},
		TotalCount: 1,
	}

	out := RawCommentList(comments, api.PullRequestReviews{})

	if strings.Contains(out, "\x1b]") {
		t.Fatalf("expected OSC escape sequence to be stripped, got: %q", out)
	}
}

func TestCommentList_SanitizesAuthorLogin(t *testing.T) {
	io, _, stdout, _ := iostreams.Test()
	maliciousLogin := "attacker\x1b]0;PWNED\x07"

	comments := api.Comments{
		Nodes: []api.Comment{
			{Author: api.CommentAuthor{Login: maliciousLogin}, Body: "hi"},
		},
		TotalCount: 1,
	}

	out, err := CommentList(io, comments, api.PullRequestReviews{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "\x1b]") {
		t.Fatalf("expected escape sequence stripped from author login, got: %q", out)
	}
	_ = stdout
}
```
Both tests currently fail against `RawCommentList`/`CommentList` as implemented (the OSC sequences pass through unchanged), demonstrating the unsanitized terminal injection path.

### Citations

**File:** pkg/cmd/pr/shared/comments.go (L29-51)
```go
func RawCommentList(comments api.Comments, reviews api.PullRequestReviews) string {
	sortedComments := sortComments(comments, reviews)
	var b strings.Builder
	for _, comment := range sortedComments {
		fmt.Fprint(&b, formatRawComment(comment))
	}
	return b.String()
}

func formatRawComment(comment Comment) string {
	if comment.IsHidden() {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "author:\t%s\n", comment.AuthorLogin())
	fmt.Fprintf(&b, "association:\t%s\n", strings.ToLower(comment.Association()))
	fmt.Fprintf(&b, "edited:\t%t\n", comment.IsEdited())
	fmt.Fprintf(&b, "status:\t%s\n", formatRawCommentStatus(comment.Status()))
	fmt.Fprintln(&b, "--")
	fmt.Fprintln(&b, comment.Content())
	fmt.Fprintln(&b, "--")
	return b.String()
}
```

**File:** pkg/cmd/pr/shared/comments.go (L97-105)
```go
	// Header
	fmt.Fprint(&b, cs.Bold(comment.AuthorLogin()))
	if comment.Status() != "" {
		fmt.Fprint(&b, formatCommentStatus(cs, comment.Status()))
	}
	if comment.Association() != "NONE" {
		fmt.Fprint(&b, cs.Boldf(" (%s)", text.Title(comment.Association())))
	}
	fmt.Fprint(&b, cs.Boldf(" • %s", text.FuzzyAgoAbbr(time.Now(), comment.Created())))
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
