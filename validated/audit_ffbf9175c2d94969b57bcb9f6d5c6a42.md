### Title
`gh pr view` writes attacker-controlled PR fields to `IO.Out`/pager bypassing the `ContentOut` ANSI sanitizer - ([File: pkg/cmd/pr/view/view.go])

### Summary
`(IOStreams).SetContentSanitization` and its paired `ContentOut` writer [1](#0-0)  are the CLI's only mechanism for stripping ANSI/OSC escape sequences from untrusted remote content before it reaches a terminal or pager. `pkg/cmd/pr/view/view.go` never routes PR data through `ContentOut`; instead `printRawPrPreview` and `printHumanPrPreview` write `pr.Title`, `pr.Body`, and other fields directly to `opts.IO.Out` with `fmt.Fprintf`/`Fprintln`, so the sanitizer is bypassed entirely regardless of the `sanitizeContent` flag.

### Finding Description
`IOStreams` maintains two output paths: `Out` (raw, app-authored content) and `ContentOut`, which wraps `Out` with `transform.NewWriter(out, &asciisanitizer.Sanitizer{})` when `sanitizeContent` is true, specifically documented as being for "external content (HTTP response bodies, gist files, etc.) where the application is not the author of the bytes" [2](#0-1) . The codebase also provides an `Untrusted` wrapper type whose `String()` method sanitizes automatically via the same asciisanitizer transform [3](#0-2) , intended to label API-response text so it can't leak unsanitized through `fmt` print paths.

In `pkg/cmd/pr/view/view.go`, `pr.Title` (attacker-settable by anyone who opens a PR against a repo) and `pr.Body` are plain `string` fields (not `Untrusted`), and are printed straight to `out := opts.IO.Out`: [4](#0-3) 
and in the human-formatted view: [5](#0-4) 

Neither function ever touches `opts.IO.ContentOut`. Because `SetContentSanitization`/`ContentOut` is opt-in per call site rather than applied globally to all writes of remote data, any command (like `pr view`) that forgets to route external content through `ContentOut` (or wrap it in `Untrusted`) emits raw bytes — including any ANSI/OSC/CSI escape sequences the PR author embedded in the title or body — straight to `IO.Out`, which is the stream backing both the terminal and the pager once `StartPager()` redirects it. The invariant "sanitization is applied before the bytes leave gh, regardless of the sink" does not hold here because sanitization is never invoked at all on this path, not because a sink-specific bypass exists.

### Impact Explanation
An unprivileged attacker who opens a pull request with a title or body containing terminal escape sequences (e.g., OSC 52 clipboard-set, cursor-repositioning/screen-clear CSI sequences, or sequences that redraw fake prompts) can have those bytes rendered unmodified in the victim's terminal or external pager when the victim runs `gh pr view <number>` (or the raw/non-TTY path via `gh pr view --json` piping, or scripted consumption). This enables terminal output/prompt spoofing — e.g., overwriting displayed text to make a malicious action look benign, or clipboard injection via OSC 52 — matching the "High: Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation" bounty class.

### Likelihood Explanation
High feasibility and full repeatability: creating a PR with a crafted title/body requires no special privileges, just the ability to open a pull request (or even just push a branch/fork depending on repo settings) against any repository the victim will later inspect with `gh pr view`. The victim needs to run only the ordinary `gh pr view` command; no opt-out flags need to be set, since the sanitization step is simply never invoked on this path.

### Recommendation
Route all remote/attacker-controlled fields in `pkg/cmd/pr/view/view.go` (`pr.Title`, `pr.Body`, labels, milestone title, project names, reviewer/assignee display names, `AutoMergeRequest.EnabledBy.Login`) through `opts.IO.ContentOut` or wrap them in `iostreams.Untrusted` before any `fmt.Fprint*` call, consistent with the pattern already used elsewhere in the codebase (e.g., `pkg/cmd/run/view/logs.go`, `pkg/cmd/gist/view/view.go`). Ideally, audit all `pr/view`, `issue/view`, `repo/view`, and similar "view" commands for the same raw-`Out` bypass pattern, since the sanitizer is opt-in per call site rather than structurally enforced.

### Proof of Concept
```go
// pkg/cmd/pr/view/view_test.go (new test)
func TestPrintRawPrPreview_TitleNotSanitized(t *testing.T) {
    ios, _, out, _ := iostreams.Test()
    pr := &api.PullRequest{
        Title: "Evil\x1b]52;c;ZXZpbA==\x07Title", // OSC 52 clipboard-injection sequence
        Body:  "body",
    }
    err := printRawPrPreview(ios, pr)
    require.NoError(t, err)
    // Expected (secure) assertion that currently FAILS:
    require.NotContains(t, out.String(), "\x1b]52;")
}
```
Running this against the current code shows the OSC escape sequence passes through unmodified into `out`, whereas the same string wrapped in `iostreams.NewUntrusted(pr.Title).String()` or written via `ContentOut` would have the sequence neutralized, per `asciisanitizer.Sanitizer` behavior exercised in `pkg/iostreams/untrusted_test.go`.

### Citations

**File:** pkg/iostreams/iostreams.go (L58-66)
```go
	// ContentOut is the writer for external content (HTTP response bodies,
	// gist files, etc.) where the application is not the author of the bytes.
	// By default it sanitizes ANSI escape sequences before they reach the
	// underlying stdout. SetContentSanitization toggles the sanitization at
	// the command layer (e.g. via an --allow-escape-sequences flag).
	ContentOut io.Writer

	sanitizeContent bool

```

**File:** pkg/iostreams/iostreams.go (L490-497)
```go
// SetContentSanitization toggles ANSI escape sanitization on ContentOut.
// Commands should call this with false when an explicit opt-out flag (e.g.
// --allow-escape-sequences) is set, so subsequent writes of external content
// pass through unmodified.
func (s *IOStreams) SetContentSanitization(enabled bool) {
	s.sanitizeContent = enabled
	s.ContentOut = newContentWriter(s.Out, enabled)
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

**File:** pkg/cmd/pr/view/view.go (L141-177)
```go
func printRawPrPreview(io *iostreams.IOStreams, pr *api.PullRequest) error {
	out := io.Out
	cs := io.ColorScheme()

	reviewers := prReviewerList(*pr, cs)
	assignees := prAssigneeList(*pr)
	labels := prLabelList(*pr, cs)
	projects := prProjectList(*pr)

	fmt.Fprintf(out, "title:\t%s\n", pr.Title)
	fmt.Fprintf(out, "state:\t%s\n", prStateWithDraft(pr))
	fmt.Fprintf(out, "author:\t%s\n", pr.Author.DisplayName())
	fmt.Fprintf(out, "labels:\t%s\n", labels)
	fmt.Fprintf(out, "assignees:\t%s\n", assignees)
	fmt.Fprintf(out, "reviewers:\t%s\n", reviewers)
	fmt.Fprintf(out, "projects:\t%s\n", projects)
	var milestoneTitle string
	if pr.Milestone != nil {
		milestoneTitle = pr.Milestone.Title
	}
	fmt.Fprintf(out, "milestone:\t%s\n", milestoneTitle)
	fmt.Fprintf(out, "number:\t%d\n", pr.Number)
	fmt.Fprintf(out, "url:\t%s\n", pr.URL)
	fmt.Fprintf(out, "additions:\t%s\n", cs.Green(strconv.Itoa(pr.Additions)))
	fmt.Fprintf(out, "deletions:\t%s\n", cs.Red(strconv.Itoa(pr.Deletions)))
	var autoMerge string
	if pr.AutoMergeRequest == nil {
		autoMerge = "disabled"
	} else {
		autoMerge = fmt.Sprintf("enabled\t%s\t%s",
			pr.AutoMergeRequest.EnabledBy.Login,
			strings.ToLower(pr.AutoMergeRequest.MergeMethod))
	}
	fmt.Fprintf(out, "auto-merge:\t%s\n", autoMerge)

	fmt.Fprintln(out, "--")
	fmt.Fprintln(out, pr.Body)
```

**File:** pkg/cmd/pr/view/view.go (L182-187)
```go
func printHumanPrPreview(opts *ViewOptions, baseRepo ghrepo.Interface, pr *api.PullRequest) error {
	out := opts.IO.Out
	cs := opts.IO.ColorScheme()

	// Header (Title and State)
	fmt.Fprintf(out, "%s %s#%d\n", cs.Bold(pr.Title), ghrepo.FullName(baseRepo), pr.Number)
```
