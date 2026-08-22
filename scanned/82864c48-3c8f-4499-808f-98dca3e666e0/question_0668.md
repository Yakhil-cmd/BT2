# Q0668: token reaches stdout/stderr/log - NewCAPIClient in client.go

## Question
Can attacker-triggered error handling in `NewCAPIClient` in [pkg/cmd/agent-task/capi/client.go](pkg/cmd/agent-task/capi/client.go#L36) echo a request URL, header, or config value that still contains the token into output, a log file, or a telemetry payload?

## Target
- File/function: [pkg/cmd/agent-task/capi/client.go:36](pkg/cmd/agent-task/capi/client.go#L36) - `NewCAPIClient`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Force an error from an attacker-controlled endpoint and read the token from the reported message in CI logs.
- Invariant to test: Credentials are redacted on every output and telemetry path.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test forcing the error branch and asserting the token string never appears in captured output.
