### Title
Terminal escape sequence injection via `gh pr view --comments` raw output - ([File: pkg/cmd/pr/view/view.go])

### Summary
`gh pr view <n> --comments` in non-TTY mode prints PR comment/review bodies via `shared.RawCommentList`, which interpolates `comment.Content()` (attacker-controlled PR comment/review body) directly into the output with no escape-sequence check or `Untrusted`-content wrapping. This differs from `gh gist view`'s raw dump path, which explicitly calls `iostreams.ContainsEscapeSequence` and refuses/guards output when not connected to a TTY.

### Finding Description
In `pkg/cmd/pr/view/view.go`, `viewRun` handles the non-TTY, `--comments` case as: [1](#0-0) 
which calls `shared.RawCommentList(pr.Comments, pr.DisplayableReviews())` and writes the result directly to `opts.IO.Out` with `fmt.Fprint`.

`RawCommentList`/`formatRawComment` in `pkg/cmd/pr/shared/comments.go` builds the raw text by writing `comment.Content()` straight into a `strings.Builder` with no sanitization, escaping, or escape-sequence check: [2](#0-1) 

`comment.Content()` returns the raw PR comment/review body text as retrieved from the GitHub API — fully attacker-controlled since any GitHub user can post a comment or review on a PR (including on a PR they opened, or via a comment on someone else's PR that they can then get the victim to view).

By contrast, `gh gist view`'s raw-dump path (`pkg/cmd/gist/view/view.go`) treats file content as untrusted (`iostreams.NewUntrusted`), and before printing to a non-TTY output explicitly checks: [3](#0-2) 
refusing output (returning an error) if `iostreams.ContainsEscapeSequence` detects an ESC byte (0x1B) unless `--allow-escape-sequences` is passed.

The PR raw-comment path has no equivalent guard: `comment.Content()` bytes (including any `\x1b[...` ANSI/CSI sequences) flow unmodified through `formatRawComment` → `RawCommentList` → `fmt.Fprint(opts.IO.Out, comments)` into whatever the victim's terminal, pipe, or redirected file consumes. `opts.IO.Out` here is the plain application-output writer, not gated by any content-sanitization or escape-sequence check the way the gist view's guarded raw dump is.

### Impact Explanation
This allows terminal escape-sequence injection into the output of `gh pr view --comments` (and `printRawPrPreview`, which similarly prints `pr.Body` unguarded via `fmt.Fprintln(out, pr.Body)`). If a victim's terminal is rendering the output live (rather than purely redirecting/piping to a non-terminal sink), malicious ANSI/OSC sequences from a PR comment/review body could manipulate terminal state, spoof prior output, move the cursor, or (depending on terminal emulator) trigger more advanced terminal-injection primitives (e.g., OSC 52 clipboard writes, title-bar spoofing, or in vulnerable terminal emulators, more severe effects). This matches GitHub's "content spoofing / terminal injection" class of impact — output-integrity compromise rather than direct code execution, since gh itself does not execute the escape sequences.

### Likelihood Explanation
High feasibility: any unprivileged GitHub user can open a PR or comment/review on a PR, and getting a victim to run `gh pr view <n> --comments` (non-TTY, e.g., in a script or CI log capture) is a very ordinary usage pattern for automation. No special permissions, tokens, or MITM are required — this is squarely within the "attacker publishes PR/comment content, victim runs ordinary gh command" threat model.

### Recommendation
Apply the same guard model used in `pkg/cmd/gist/view/view.go`: wrap comment/review bodies (and `pr.Body` in `printRawPrPreview`) with `iostreams.NewUntrusted`, and before writing to a non-TTY `opts.IO.Out`, check `iostreams.ContainsEscapeSequence` on the raw content and either strip/refuse it (matching gist view's behavior) or route it through a sanitizing/`ContentOut`-equivalent writer that renders escape bytes inert.

### Proof of Concept
```go
// pkg/cmd/pr/view/view_test.go (new test)
func TestPRView_Comments_EscapeSequenceNotSanitized(t *testing.T) {
    http := &httpmock.Registry{}
    defer http.Verify(t)
    shared.RunCommandFinder("13", &api.PullRequest{
        Number: 13,
        Comments: api.Comments{Nodes: []*api.Comment{
            {Body: "hello\x1b[31mINJECTED\x1b[0m", Author: api.Author{Login: "attacker"}},
        }},
    }, baseRepo)

    io, _, stdout, _ := iostreams.Test()
    io.SetStdoutTTY(false) // non-TTY, matches "gh pr view --comments | cat"

    _, err := runCommand(http, nil, "13", true /* comments */, io)
    require.NoError(t, err)

    // Expected (after fix): ESC byte stripped/rejected, matching gist view guard
    assert.NotContains(t, stdout.Bytes(), []byte{0x1B})
    // Current behavior: raw ESC byte passes through unmodified
}
```
Expected result today: the ESC byte (`0x1B`) is present verbatim in `stdout`, confirming the missing guard compared to `pkg/cmd/gist/view/view.go`'s `ContainsEscapeSequence` check.

### Citations

**File:** pkg/cmd/pr/view/view.go (L133-136)
```go
	if opts.Comments {
		fmt.Fprint(opts.IO.Out, shared.RawCommentList(pr.Comments, pr.DisplayableReviews()))
		return nil
	}
```

**File:** pkg/cmd/pr/shared/comments.go (L38-51)
```go
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

**File:** pkg/cmd/gist/view/view.go (L183-196)
```go
		// Raw dump. On a terminal, ContentOut renders escape sequences inert.
		// When the output is piped, refuse content carrying escape sequences
		// rather than silently rewriting the bytes; --allow-escape-sequences
		// forces raw.
		if !opts.AllowEscapeSequences && !opts.IO.IsStdoutTTY() {
			if iostreams.ContainsEscapeSequence(content.RawBytes()) {
				return errors.New("gist file contains terminal escape sequences; pass --allow-escape-sequences to view it anyway")
			}
			opts.IO.SetContentSanitization(false)
		}
		raw := content.Raw()
		if _, err := fmt.Fprint(opts.IO.ContentOut, raw); err != nil {
			return err
		}
```
