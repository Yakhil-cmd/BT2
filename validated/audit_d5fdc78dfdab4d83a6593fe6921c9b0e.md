### Title
Unsanitized artifact names from `ListArtifacts` are printed to the terminal, enabling ANSI/control-sequence injection - (File: pkg/cmd/run/shared/artifacts.go / pkg/cmd/run/view/view.go)

### Summary
`ListArtifacts` in [1](#0-0)  fetches the `Artifact.Name` field verbatim from the GitHub Actions API response and returns it to callers with no sanitization. `gh run view` then writes that attacker-controlled string directly to the terminal via `fmt.Fprintf(out, "%s%s\n", a.Name, expiredBadge)` [2](#0-1) , unlike several other display paths in the codebase that explicitly sanitize untrusted text before printing.

### Finding Description
`Artifact.Name` is populated straight from the JSON API response with no escaping: [3](#0-2) . Since GitHub Actions lets any workflow author (including an unprivileged contributor whose workflow runs, e.g., on `pull_request` or via a fork PR) name an uploaded artifact arbitrarily, an attacker can set the artifact name to a string containing terminal control/escape sequences (e.g., ANSI cursor movement, alternate screen buffer, OSC hyperlink/title sequences, or sequences that clear the visible output).

When the victim runs `gh run view <run-id>` (or `gh run view <run-id> --json artifacts` with certain renderers), the code path is:
1. `runView` calls artifact listing which ultimately hits `ListArtifacts` — the JSON payload is decoded and `Artifacts` returned unmodified.
2. In the "ARTIFACTS" section, each artifact name is printed with `fmt.Fprintf(out, "%s%s\n", a.Name, expiredBadge)` — no call to any sanitizer.

By contrast, other places in the CLI that render remote/untrusted text explicitly strip control sequences before printing, e.g. `pkg/cmd/gist/view/view.go`, `pkg/cmd/pr/diff/diff.go`, `pkg/cmd/release/download/download.go`, and `pkg/cmd/repo/read-file/read_file.go`, all of which reference `SanitizeControlSequences`/`iostreams/untrusted.go`. `pkg/cmd/run/view/view.go` has no such call for the artifact name, indicating this specific rendering path was missed by that sanitization pattern.

### Impact Explanation
This matches "Terminal output/prompt spoofing" impact: a malicious artifact name can hide or rewrite terminal output (e.g., clear-screen sequences to hide earlier output, or crafted text that visually mimics a shell prompt or confirmation dialog), potentially tricking a victim into taking an unintended action or misreading run status. It does not achieve code execution or credential theft directly, but is a legitimate terminal-spoofing primitive as scoped by the target impact class.

### Likelihood Explanation
Any unprivileged GitHub user can upload an artifact with an attacker-chosen name in a public repository/fork workflow run and get a victim (maintainer, reviewer) to run `gh run view` against that run — a very common, low-effort action. No special permissions beyond triggering a workflow run (e.g., via a fork PR) are needed, so this is fully reachable by the described unprivileged attacker.

### Recommendation
Sanitize `a.Name` (and any other API-supplied strings rendered in `gh run view`, such as job/step names if not already handled) using the existing `SanitizeControlSequences`/`iostreams` untrusted-text helper before writing to `out`, consistent with `gist/view`, `pr/diff`, `release/download`, and `repo/read-file`.

### Proof of Concept
Go test sketch for `pkg/cmd/run/view/view_test.go`, following the existing "with artifacts" test pattern [4](#0-3) :
```go
reg.Register(
    httpmock.REST("GET", "repos/OWNER/REPO/actions/runs/3/artifacts"),
    httpmock.JSONResponse(map[string][]shared.Artifact{
        "artifacts": {
            shared.Artifact{Name: "\x1b[2J\x1b[HHIJACKED", Expired: false},
        },
    }))
```
Assert that `wantOut` contains the raw escape bytes (proving no sanitization occurred) — i.e., the test would fail an assertion that expects the escape sequence to be stripped/escaped, confirming the gap. A golden/fixture-based acceptance test (similar to `acceptance/testdata/workflow/run-view-log-escape-sequences.txtar`, which exists for log rendering but not for artifact names) should be added for `gh run view` artifact listing.

### Citations

**File:** pkg/cmd/run/shared/artifacts.go (L12-21)
```go
type Artifact struct {
	Name        string `json:"name"`
	Size        uint64 `json:"size_in_bytes"`
	DownloadURL string `json:"archive_download_url"`
	Expired     bool   `json:"expired"`
}

type artifactsPayload struct {
	Artifacts []Artifact
}
```

**File:** pkg/cmd/run/shared/artifacts.go (L23-59)
```go
func ListArtifacts(httpClient *http.Client, repo ghrepo.Interface, runID string) ([]Artifact, error) {
	var results []Artifact

	perPage := 100
	u, err := safeurl.JoinPath("repos", repo.RepoOwner(), repo.RepoName(), "actions", "artifacts")
	if err != nil {
		return nil, err
	}
	if runID != "" {
		u, err = safeurl.JoinPath("repos", repo.RepoOwner(), repo.RepoName(), "actions", "runs", runID, "artifacts")
		if err != nil {
			return nil, err
		}
	}
	u.SetQuery("per_page", strconv.Itoa(perPage))
	var pageURL safeurl.SafeURL = u

	// TODO(api-client-rollout)
	// This line of code is part of a mechanical roll out of the api client.
	// As a follow up, consider whether the api client can be injected to this call site, rather than constructed
	client := api.NewClientFromHTTP(httpClient)

	for {
		var payload artifactsPayload
		nextURL, err := client.RESTWithNext(repo.RepoHost(), http.MethodGet, pageURL.String(), nil, &payload)
		if err != nil {
			return nil, err
		}
		results = append(results, payload.Artifacts...)

		if nextURL == "" {
			break
		}
		pageURL = safeurl.NewImmutableSafeURL(nextURL)
	}

	return results, nil
```

**File:** pkg/cmd/run/view/view.go (L416-426)
```go
	if selectedJob == nil {
		if len(artifacts) > 0 {
			fmt.Fprintln(out)
			fmt.Fprintln(out, cs.Bold("ARTIFACTS"))
			for _, a := range artifacts {
				expiredBadge := ""
				if a.Expired {
					expiredBadge = cs.Muted(" (expired)")
				}
				fmt.Fprintf(out, "%s%s\n", a.Name, expiredBadge)
			}
```

**File:** pkg/cmd/run/view/view_test.go (L369-413)
```go
		{
			name: "with artifacts",
			opts: &ViewOptions{
				RunID: "3",
			},
			httpStubs: func(reg *httpmock.Registry) {
				reg.Register(
					httpmock.REST("GET", "repos/OWNER/REPO/actions/runs/3"),
					httpmock.JSONResponse(shared.SuccessfulRun))
				reg.Register(
					httpmock.REST("GET", "repos/OWNER/REPO/actions/runs/3/artifacts"),
					httpmock.JSONResponse(map[string][]shared.Artifact{
						"artifacts": {
							shared.Artifact{Name: "artifact-1", Expired: false},
							shared.Artifact{Name: "artifact-2", Expired: true},
							shared.Artifact{Name: "artifact-3", Expired: false},
						},
					}))
				reg.Register(
					httpmock.GraphQL(`query PullRequestForRun`),
					httpmock.StringResponse(``))
				reg.Register(
					httpmock.REST("GET", "runs/3/jobs"),
					httpmock.JSONResponse(shared.JobsPayload{}))
				reg.Register(
					httpmock.REST("GET", "repos/OWNER/REPO/actions/workflows/123"),
					httpmock.JSONResponse(shared.TestWorkflow))
			},
			wantOut: heredoc.Doc(`

				✓ trunk CI · 3
				Triggered via push about 59 minutes ago

				JOBS


				ARTIFACTS
				artifact-1
				artifact-2 (expired)
				artifact-3

				For more information about a job, try: gh run view --job=<job-id>
				View this run on GitHub: https://github.com/runs/3
			`),
		},
```
