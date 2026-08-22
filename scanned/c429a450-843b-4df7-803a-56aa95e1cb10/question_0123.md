# Q0123: token reaches stdout/stderr/log - NewCmdApi in api.go

## Question
Can attacker-triggered error handling in `NewCmdApi` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L66) echo a request URL, header, or config value that still contains the token into output, a log file, or a telemetry payload?

## Target
- File/function: [pkg/cmd/api/api.go:66](pkg/cmd/api/api.go#L66) - `NewCmdApi`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Force an error from an attacker-controlled endpoint and read the token from the reported message in CI logs.
- Invariant to test: Credentials are redacted on every output and telemetry path.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test forcing the error branch and asserting the token string never appears in captured output.
