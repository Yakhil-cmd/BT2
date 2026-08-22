# Q4784: retry amplification - loadContent in read_file.go

## Question
Can an attacker-controlled endpoint reached from `loadContent` in [pkg/cmd/repo/read-file/read_file.go](pkg/cmd/repo/read-file/read_file.go#L216) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [pkg/cmd/repo/read-file/read_file.go:216](pkg/cmd/repo/read-file/read_file.go#L216) - `loadContent`
- Entrypoint: gh repo read-file
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
