### No vulnerability found for this question.

The `fetchReleasePath` function in [1](#0-0)  receives an already-constructed `safeurl.SafeURL` value and merely calls `url.String()` before issuing the request; it performs no string concatenation of attacker-controlled values itself.

All callers build that URL via `safeurl.JoinPathWithHostPrefix`, e.g. [2](#0-1)  and [3](#0-2) , passing `tagName` and other path components as separate arguments rather than pre-concatenated strings.

The `safeurl` package's `joinPath` helper percent-encodes each component individually with `url.PathEscape` before joining with `/`, and `checkTraversal` explicitly rejects a component that is exactly `".."`: [4](#0-3)  and [5](#0-4) . Query parameters set via `SetQuery` are similarly encoded through `url.Values.Encode()` when rendering the URL: [6](#0-5) .

Because `url.PathEscape` percent-encodes `/`, `?`, `#`, and any literal `%` (preventing `%0d%0a`-style pre-encoded CRLF from surviving as a decodable sequence), a hostile tag/branch/asset name cannot alter the path structure or introduce a new query/fragment/CRLF-decoded segment. This directly satisfies the stated invariant ("All path segments are URL-escaped individually before assembly"), so the described exploit path is not reachable in the current code.

### Citations

**File:** pkg/cmd/release/shared/fetch.go (L193-196)
```go
	publishedURL, err := safeurl.JoinPathWithHostPrefix(ghinstance.RESTPrefix(repo.RepoHost()), "repos", repo.RepoOwner(), repo.RepoName(), "releases", "tags", tagName)
	if err != nil {
		return nil, err
	}
```

**File:** pkg/cmd/release/shared/fetch.go (L238-242)
```go
	url, err := safeurl.JoinPathWithHostPrefix(ghinstance.RESTPrefix(repo.RepoHost()), "repos", repo.RepoOwner(), repo.RepoName(), "releases", "latest")
	if err != nil {
		return nil, err
	}
	return fetchReleasePath(ctx, httpClient, url)
```

**File:** pkg/cmd/release/shared/fetch.go (L281-298)
```go
func fetchReleasePath(ctx context.Context, httpClient *http.Client, url safeurl.SafeURL) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, ErrReleaseNotFound
	} else if resp.StatusCode > 299 {
		return nil, api.HandleHTTPError(resp)
	}
```

**File:** internal/safeurl/safeurl.go (L75-82)
```go
func checkTraversal(components []string) error {
	for _, c := range components {
		if c == ".." {
			return fmt.Errorf("path component %q would traverse the URL path", c)
		}
	}
	return nil
}
```

**File:** internal/safeurl/safeurl.go (L86-103)
```go
// SetQuery sets the query parameter key to value, replacing any existing value.
func (u *MutableSafeURL) SetQuery(key, value string) {
	if u.query == nil {
		u.query = url.Values{}
	}
	u.query.Set(key, value)
}

// String renders the full URL. Path components and query parameters are URL encoded
// (aka percent-encoded) while the host prefix is included as given. The zero value
// renders as the empty string.
func (u *MutableSafeURL) String() string {
	result := joinPathWithHostPrefix(u.prefix, u.components...)
	if len(u.query) > 0 {
		result += "?" + u.query.Encode()
	}
	return result
}
```

**File:** internal/safeurl/safeurl.go (L131-145)
```go
// joinPath builds a REST API URL path by percent-encoding each component with
// url.PathEscape and joining them with single slash separators.
//
// With no components, the empty string is returned.
func joinPath(components ...string) string {
	// We build the path by hand rather than with url.JoinPath because url.JoinPath runs path.Clean
	// on the result, which resolves any "." or ".." segments. Percent-encoding does not encode dots,
	// so a component equal to "." or ".." would survive escaping and then be collapsed by the clean,
	// silently changing which resource the path addresses.
	escaped := make([]string, len(components))
	for i, c := range components {
		escaped[i] = url.PathEscape(c)
	}
	return strings.Join(escaped, "/")
}
```
