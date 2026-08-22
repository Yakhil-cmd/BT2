# Q5808: token reaches stdout/stderr/log - (Client).Pull in client.go

## Question
Can attacker-triggered error handling in `Pull` in [git/client.go](git/client.go#L881) echo a request URL, header, or config value that still contains the token into output, a log file, or a telemetry payload?

## Target
- File/function: [git/client.go:881](git/client.go#L881) - `(Client).Pull`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Force an error from an attacker-controlled endpoint and read the token from the reported message in CI logs.
- Invariant to test: Credentials are redacted on every output and telemetry path.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test forcing the error branch and asserting the token string never appears in captured output.
