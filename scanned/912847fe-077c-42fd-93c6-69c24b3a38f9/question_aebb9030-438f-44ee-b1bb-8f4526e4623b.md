[File: 'internal/ghrepo/repo.go' -

### Citations

**File:** internal/ghrepo/repo.go (L26-32)
```go
func NewWithHost(owner, repo, hostname string) Interface {
	return &ghRepo{
		owner:    owner,
		name:     repo,
		hostname: normalizeHostname(hostname),
	}
}
```

**File:** internal/ghrepo/repo.go (L60-72)
```go
// FromURL extracts the GitHub repository information from a git remote URL
func FromURL(u *url.URL) (Interface, error) {
	if u.Hostname() ==
