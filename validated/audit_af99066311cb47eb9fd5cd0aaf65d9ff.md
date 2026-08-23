### Title
Unbounded attacker-controlled content size causes local resource-exhaustion DOS when `gh` renders markdown (`markdown.Render`/glamour) - ([File: pkg/markdown/markdown.go])

### Summary
The reported Hats.uri bug class is: an attacker-controlled, unbounded-length string is later processed by a function that any caller must pay for, with no size cap enforced at write time, leading to a DOS/expensive-execution for whoever reads it. The closest reachable analog in `gh` is markdown rendering of remote, attacker-authored content (gist files, issue/PR/discussion bodies, release notes, project READMEs) through the shared `markdown.Render` helper, which wraps `glamour`'s Goldmark-based renderer with no upper bound on input size before parsing/rendering.

### Finding Description
Every "view" command that displays user-generated content funnels it through `markdown.Render`: [1](#0-0) 
This function only bounds the *display width* (`WithWrap`, capped at 120 chars) — it does not bound the *size* of the input string that is parsed and laid out. Callers such as:
- `gh gist view` renders gist file content, including a full, non-truncated raw file fetched separately when GitHub's inline response is truncated [2](#0-1) 
- `gh issue view`, `gh pr view`, `gh discussion view`, `gh release view`, `gh repo view`, `gh project view`, and PR/issue comment rendering all pass API-supplied `Body`/`Content` strings straight into `markdown.Render` with no length check [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

An unprivileged remote actor who can author any of these artifacts (a public gist, an issue/PR/comment/discussion on a repo they have write/comment access to, or a release on their own repo) can supply pathological markdown — either extremely large raw content (particularly gist raw files, which are fetched in full with no evident size cap: `shared.GetRawGistFile`) or algorithmically expensive markdown constructs (deeply nested lists/blockquotes/tables) — that becomes expensive for Goldmark/glamour to parse and lay out. Any victim who simply views that content with `gh` pays the CPU/memory cost locally, which can hang or crash their terminal session.

By contrast, the codebase shows the project is otherwise conscious of exactly this class of problem: it caps blob fetch size in `gh skills preview` (`maxBytes cap stops fetching`) and defends against terminal-escape-sequence injection everywhere via the `iostreams.Untrusted` wrapper, `ContainsEscapeSequence`, and `CopyGuardedContent`. There is no equivalent cap applied before markdown rendering of remotely-sourced bodies.

### Impact Explanation
A victim who runs an ordinary `gh` viewing command against attacker-controlled content (a gist link they were sent, a PR/issue/discussion they were asked to review, a release page) can have their local `gh` process consume excessive CPU/memory or hang indefinitely while rendering the markdown, denying them normal use of the CLI until they kill the process. This is a local, client-side DOS triggered purely by content the attacker publishes — no elevated privileges or MITM position required, matching the "untrusted terminal output" bug class named in scope.

### Likelihood Explanation
Moderate. Creating a gist, issue, PR, comment, discussion post, or release with an oversized or pathological body is trivial and requires no special permissions beyond normal content-creation rights (which are often open, e.g., public gists or open-comment repos). The main uncertainty is whether GitHub's server-side API enforces a low enough body-size ceiling for issues/PRs/comments to make the "huge string" variant impractical (GitHub does cap most body fields at tens of thousands of characters), which would leave the "pathological/nested markdown structure" variant (rather than raw size) as the more realistic vector — that variant is harder to size without testing against the actual Goldmark/glamour renderer.

### Recommendation
- Impose an explicit maximum size (and/or a nesting-depth guard) on any string passed into `markdown.Render`, mirroring the existing `maxBytes` cap already used in `pkg/cmd/skills/preview`, and fall back to raw/plain-text output (or truncate with a notice) when the limit is exceeded.
- Apply the same cap when fetching a gist's full raw content in `shared.GetRawGistFile`, rather than fetching and rendering arbitrarily large files in full.
- Consider running `markdown.Render` calls for remote content with an execution timeout so a pathological document degrades gracefully instead of hanging the process.

### Proof of Concept
Conceptual (not verified against the live renderer, since the exact `GetRawGistFile` size-limiting behavior could not be confirmed in this session):
1. Attacker creates a public gist with a Markdown file (`.md`) whose raw content is either (a) many megabytes of plain text/markdown, or (b) a small file containing thousands of deeply nested markdown list/blockquote/table constructs known to be expensive for CommonMark parsers.
2. Attacker shares the gist URL with the victim.
3. Victim runs `gh gist view <id>`; the CLI fetches the full raw file (since GitHub truncates the inline API response for large files, the raw path is fetched without a further size cap) and passes it to `markdown.Render`.
4. The victim's `gh` process spends excessive CPU/memory during Goldmark/glamour parsing and layout, hanging or exhausting resources on their machine.

**Uncertainty flagged:** I could not retrieve the exact contents of `pkg/cmd/gist/shared/shared.go` (specifically `GetRawGistFile`) in this session to confirm whether a size limit already exists there, nor could I benchmark glamour/Goldmark's actual behavior on pathological input within this codebase. If a Devin session with full repo access is available, these should be checked directly before treating this as confirmed exploitable.

### Citations

**File:** pkg/markdown/markdown.go (L38-40)
```go
func Render(text string, opts ...glamour.TermRendererOption) (string, error) {
	return ghMarkdown.Render(text, opts...)
}
```

**File:** pkg/cmd/gist/view/view.go (L148-181)
```go
	render := func(gf *shared.GistFile) error {
		// Treat the file content as untrusted external bytes. The truncated
		// path fetches the full content from the raw URL.
		content := iostreams.NewUntrusted(gf.Content)
		if gf.Truncated {
			fullContent, err := shared.GetRawGistFile(client, safeurl.NewImmutableSafeURL(gf.RawURL))
			if err != nil {
				return err
			}

			content = fullContent
		}

		if shared.IsBinaryContents(content.RawBytes()) {
			if len(gist.Files) == 1 || opts.Filename != "" {
				return fmt.Errorf("error: file is binary")
			}
			_, err = fmt.Fprintln(opts.IO.Out, cs.Muted("(skipping rendering binary content)"))
			return nil
		}

		if strings.Contains(gf.Type, "markdown") && !opts.Raw {
			// Markdown rendering emits application-styled output to Out, so its
			// input is sanitized here; --allow-escape-sequences applies to the
			// raw dump below.
			rendered, err := markdown.Render(content.String(),
				markdown.WithTheme(opts.IO.TerminalTheme()),
				markdown.WithWrap(opts.IO.TerminalWidth()))
			if err != nil {
				return err
			}
			_, err = fmt.Fprint(opts.IO.Out, rendered)
			return err
		}
```

**File:** pkg/cmd/issue/view/view.go (L300-312)
```go
	// Body
	var md string
	var err error
	if issue.Body == "" {
		md = fmt.Sprintf("\n  %s\n\n", cs.Muted("No description provided"))
	} else {
		md, err = markdown.Render(issue.Body,
			markdown.WithTheme(opts.IO.TerminalTheme()),
			markdown.WithWrap(opts.IO.TerminalWidth()))
		if err != nil {
			return err
		}
	}
```

**File:** pkg/cmd/pr/view/view.go (L267-277)
```go
	if pr.Body == "" {
		md = fmt.Sprintf("\n  %s\n\n", cs.Muted("No description provided"))
	} else {
		md, err = markdown.Render(pr.Body,
			markdown.WithTheme(opts.IO.TerminalTheme()),
			markdown.WithWrap(opts.IO.TerminalWidth()))
		if err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "\n%s\n", md)
```

**File:** pkg/cmd/pr/shared/comments.go (L121-134)
```go
	// Body
	var md string
	var err error
	if comment.Content() == "" {
		md = fmt.Sprintf("\n  %s\n\n", cs.Muted("No body provided"))
	} else {
		md, err = markdown.Render(comment.Content(),
			markdown.WithTheme(io.TerminalTheme()),
			markdown.WithWrap(io.TerminalWidth()))
		if err != nil {
			return "", err
		}
	}
	fmt.Fprint(&b, md)
```

**File:** pkg/cmd/discussion/view/view.go (L374-386)
```go
	var md string
	if d.Body == "" {
		md = fmt.Sprintf("\n  %s\n\n", cs.Muted("No description provided"))
	} else {
		var err error
		md, err = markdown.Render(d.Body,
			markdown.WithTheme(opts.IO.TerminalTheme()),
			markdown.WithWrap(opts.IO.TerminalWidth()))
		if err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "\n%s\n", md)
```

**File:** pkg/cmd/release/view/view.go (L147-153)
```go
	renderedDescription, err := markdown.Render(release.Body,
		markdown.WithTheme(io.TerminalTheme()),
		markdown.WithWrap(io.TerminalWidth()))
	if err != nil {
		return err
	}
	fmt.Fprintln(w, renderedDescription)
```
