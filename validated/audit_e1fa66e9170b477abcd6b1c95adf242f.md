### Title
Ruleset and release `view --web` pass unvalidated API-supplied URLs directly to `Browser.Browse` - ([File: pkg/cmd/ruleset/view/view.go], [File: pkg/cmd/release/view/view.go])

### Summary
`gh ruleset view --web` and `gh release view --web` call `opts.Browser.Browse()` directly on `rs.Links.Html.Href` and `release.URL`, both of which are populated verbatim from an API JSON response, with no scheme or format validation anywhere in the call path. This differs from `pkg/cmd/repo/view/view.go`, where the URL passed to `Browse` (`openURL`) is not attacker-influenced text but is synthesized locally via `ghrepo.GenerateRepoURL`, which hardcodes the `https://` scheme.

### Finding Description
`internal/browser/browser.go` defines `Browser.Browse(string) error` with no validation whatsoever [1](#0-0) , delegating directly to `ghBrowser.New` from `go-gh`.

- In `pkg/cmd/ruleset/view/view.go`, `viewRun` calls `opts.Browser.Browse(rs.Links.Html.Href)`, where `rs` is a `*shared.RulesetREST` populated from `viewRepoRuleset`/`viewOrgRuleset` API responses, with no scheme or length check before the call [2](#0-1) .
- In `pkg/cmd/release/view/view.go`, `viewRun` calls `opts.Browser.Browse(release.URL)`, where `release.URL` comes from `shared.FetchRelease`/`shared.FetchLatestRelease` API responses, again with no validation [3](#0-2) .
- By contrast, `pkg/cmd/repo/view/view.go` builds `openURL` via `generateBranchURL`, which calls `ghrepo.GenerateRepoURL(r, ...)` — this constructs the URL from already-validated `ghrepo.Interface` components (host/owner/name), not a raw attacker-controlled string field, and always emits an `https://` URL [4](#0-3) [5](#0-4) .
- Notably, the only existing check in the codebase, `prShared.ValidURL` (used in `pkg/cmd/issue/create/create.go`), does **not** validate scheme at all — it only checks string length is under 8192 bytes: `func ValidURL(urlStr string) bool { return len(urlStr) < 8192 }` [6](#0-5) . So even the one call site that performs a "validation" step would not reject `file://`, `javascript:`, or a custom registered URI scheme.

### Impact Explanation
If a malicious or compromised host that a victim has configured `gh` to point at (a rogue GitHub Enterprise Server instance, matching the permitted "controls responses from a host the victim points gh at" attacker capability) returns a ruleset or release payload with an `Html.Href`/`URL` field set to a non-`http(s)` URI (e.g., `file:///etc/passwd`, or a locally registered custom scheme handler), that value is passed unmodified to the OS-level browser-opening call when the victim runs `gh ruleset view --web` or `gh release view --web`. This falls under HOST_TRUST / NO_INJECTED_EXECUTION concerns, potentially exposing local files via the OS default handler for `file://` or invoking unintended local URI-scheme handlers registered on the victim's machine, corresponding to a low-to-moderate "unexpected local resource access" bounty impact class rather than remote code execution.

### Likelihood Explanation
Exploitation strictly requires the victim to be querying an API host that is attacker-controlled (a rogue/compromised GHES instance the victim has explicitly configured `gh` to use) or a compromised legitimate host, since for github.com the `Html.Href`/`URL` fields are computed server-side by GitHub and not attacker-writable through repo/release/ruleset content alone. This narrows the practical likelihood significantly compared to a fully unprivileged "publish a malicious repo" scenario; it is not exploitable purely by an attacker publishing content on github.com.

### Recommendation
Add a shared, scheme-aware `ValidURL`-style check (validating `url.Parse(u).Scheme` is exactly `http` or `https`) and call it uniformly in every `viewRun`-style function before invoking `opts.Browser.Browse`, including `pkg/cmd/ruleset/view/view.go` and `pkg/cmd/release/view/view.go`. Also strengthen `pkg/cmd/pr/shared.ValidURL` to check scheme, not just length, since it currently provides no real protection to the one call site that already uses it.

### Proof of Concept
```go
// pkg/cmd/ruleset/view/view_test.go (illustrative)
func TestViewRunWebRejectsNonHTTPScheme(t *testing.T) {
    reg := &httpmock.Registry{}
    // stub REST response for ruleset with a malicious Html.Href
    reg.Register(
        httpmock.REST("GET", "repos/OWNER/REPO/rulesets/1"),
        httpmock.JSONResponse(map[string]interface{}{
            "id": 1, "name": "test",
            "_links": map[string]interface{}{"html": map[string]string{"href": "file:///etc/passwd"}},
        }),
    )
    fakeBrowser := &browser.Stub{}
    opts := &ViewOptions{
        HttpClient: func() (*http.Client, error) { return &http.Client{Transport: reg}, nil },
        BaseRepo:   func() (ghrepo.Interface, error) { return ghrepo.New("OWNER", "REPO"), nil },
        Browser:    fakeBrowser,
        WebMode:    true,
        ID:         "1",
        IO:         iostreams.Test(),
    }
    err := viewRun(opts)
    require.NoError(t, err)
    // Expected (currently failing): Browse should never be invoked with a non-http(s) scheme
    fakeBrowser.Verify(t, "") // asserts BrowsedURL was never set / call was rejected
}
```
This test currently fails because `viewRun` unconditionally calls `opts.Browser.Browse("file:///etc/passwd")`; the same pattern applies to `pkg/cmd/release/view/view.go` using `shared.FetchRelease`/`FetchLatestRelease` httpmock stubs with a malicious `release.URL`.

### Citations

**File:** internal/browser/browser.go (L9-11)
```go
type Browser interface {
	Browse(string) error
}
```

**File:** pkg/cmd/ruleset/view/view.go (L175-185)
```go
	if opts.WebMode {
		if rs != nil {
			if opts.IO.IsStdoutTTY() {
				fmt.Fprintf(opts.IO.Out, "Opening %s in your browser.\n", text.DisplayURL(rs.Links.Html.Href))
			}

			return opts.Browser.Browse(rs.Links.Html.Href)
		} else {
			fmt.Fprintf(w, "ruleset not found\n")
		}
	}
```

**File:** pkg/cmd/release/view/view.go (L101-106)
```go
	if opts.WebMode {
		if opts.IO.IsStdoutTTY() {
			fmt.Fprintf(opts.IO.ErrOut, "Opening %s in your browser.\n", text.DisplayURL(release.URL))
		}
		return opts.Browser.Browse(release.URL)
	}
```

**File:** pkg/cmd/repo/view/view.go (L132-138)
```go
	openURL := generateBranchURL(toView, opts.Branch)
	if opts.Web {
		if opts.IO.IsStdoutTTY() {
			fmt.Fprintf(opts.IO.ErrOut, "Opening %s in your browser.\n", text.DisplayURL(openURL))
		}
		return opts.Browser.Browse(openURL)
	}
```

**File:** pkg/cmd/repo/view/view.go (L227-233)
```go
func generateBranchURL(r ghrepo.Interface, branch string) string {
	if branch == "" {
		return ghrepo.GenerateRepoURL(r, "")
	}

	return ghrepo.GenerateRepoURL(r, "tree/%s", url.QueryEscape(branch))
}
```

**File:** pkg/cmd/pr/shared/params.go (L54-57)
```go
// Maximum length of a URL: 8192 bytes
func ValidURL(urlStr string) bool {
	return len(urlStr) < 8192
}
```
