# Q4071: GraphQL query assembled from remote strings - loadContent in read_file.go

## Question
Can an asset, artifact, gist, or archive-member name and its bytes reach the query/variable construction in `loadContent` in [pkg/cmd/repo/read-file/read_file.go](pkg/cmd/repo/read-file/read_file.go#L216) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/repo/read-file/read_file.go:216](pkg/cmd/repo/read-file/read_file.go#L216) - `loadContent`
- Entrypoint: gh repo read-file
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
